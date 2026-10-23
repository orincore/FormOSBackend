const { webcrypto } = require('crypto');
const Document = require('../models/Document');

const { subtle } = webcrypto;
const KDF = { iterations: 600000, hash: 'SHA-256' }; // the same values the browser uses (keyDerivation.ts)
const b64 = (value) => Buffer.from(String(value), 'base64');
const asJson = (value) => (typeof value === 'string' ? JSON.parse(value) : value);

// Opens a Security V2 vault with the member's PIN, exactly as the browser does: the PIN and the saved
// salt make a key, that key unwraps the user data key, and that key decrypts the stored fields. Only
// someone who knows the PIN can do it. The keys and the decrypted data live in memory for a short
// window set by the caller and are never written anywhere.
async function unlockDataKey(user, pin) {
  if (!user.userSalt || !user.wrappedUserKey) throw Object.assign(new Error('This account has no vault keys.'), { code: 'NO_KEYS' });
  const base = await subtle.importKey('raw', Buffer.from(String(pin), 'utf8'), { name: 'PBKDF2' }, false, ['deriveKey']);
  const kek = await subtle.deriveKey(
    { name: 'PBKDF2', salt: b64(user.userSalt), iterations: KDF.iterations, hash: KDF.hash },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['wrapKey', 'unwrapKey', 'encrypt', 'decrypt']
  );
  const wrapped = asJson(user.wrappedUserKey);
  try {
    return await subtle.unwrapKey('raw', b64(wrapped.ct), kek, { name: 'AES-GCM', iv: b64(wrapped.iv), tagLength: 128 }, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  } catch {
    throw Object.assign(new Error('That PIN did not open the vault.'), { code: 'BAD_PIN' });
  }
}

async function decryptPayload(raw, key) {
  const payload = asJson(raw);
  if (!payload || payload.v !== 'formos_v2_aes_gcm_pbkdf2') throw new Error('Unsupported encrypted data');
  const plain = Buffer.from(await subtle.decrypt({ name: 'AES-GCM', iv: b64(payload.iv), tagLength: 128 }, key, b64(payload.ct))).toString('utf8');
  if (plain.startsWith('{') || plain.startsWith('[')) { try { return JSON.parse(plain); } catch { return plain; } }
  return plain;
}

const FIELDS = ['fullName', 'fatherName', 'dateOfBirth', 'gender', 'aadhaarNumber', 'panNumber', 'passportNumber', 'drivingLicenseNumber', 'address', 'pincode', 'state', 'phone', 'email'];
const real = (v) => typeof v === 'string' && v.trim() && !v.includes('•');

// Everything readable about a V2 member, decrypted: their profile and what was read from each document.
async function openVault(user, pin) {
  const key = await unlockDataKey(user, pin);
  const profile = { fullName: user.name || '', email: user.email || '', phone: user.phone || '' };

  if (user.encryptedProfile) {
    try {
      const data = await decryptPayload(user.encryptedProfile, key);
      if (data && typeof data === 'object') {
        FIELDS.forEach((f) => { if (real(data[f])) profile[f] = data[f]; });
        if (real(data.name) && !data.fullName) profile.fullName = data.name;
      }
    } catch { /* an unreadable profile just means fewer details */ }
  }

  const rows = await Document.find({ userId: user._id, securityVersion: 2 }).sort({ uploadedAt: -1 }).limit(30).select('_id encryptedStructuredData encryptedText uploadedAt').lean();
  const docFields = require('./documentFields');
  const docs = [];
  for (const row of rows) {
    if (!row.encryptedStructuredData) continue;
    try {
      const data = await decryptPayload(row.encryptedStructuredData, key);
      if (!data || typeof data !== 'object') continue;
      const fields = {};
      FIELDS.forEach((f) => { if (real(data[f])) fields[f] = data[f]; });
      // Everything else the document holds (vehicle class, roll number, marks...) comes with it.
      Object.entries(data).forEach(([k, v]) => { if (!(k in fields) && !docFields.HIDDEN_KEYS.has(k) && /^[A-Za-z][A-Za-z0-9]{0,39}$/.test(k) && typeof v === 'string' && real(v)) fields[k] = v; });
      // A document saved before fields were read (or by another app version) is read now, in memory, from its own text.
      if (Object.keys(fields).length <= FIELDS.filter((f) => fields[f]).length && row.encryptedText) {
        try {
          const text = await decryptPayload(row.encryptedText, key);
          if (typeof text === 'string' && text.length > 20) {
            const extra = await docFields.extractFields({ text, known: fields });
            Object.entries(extra.fields).forEach(([k, v]) => { if (!(k in fields)) fields[k] = v; });
          }
        } catch { /* the stored fields are still used */ }
      }
      docs.push({ id: String(row._id), name: data.documentName || data.originalName || 'Document', title: data.documentTitle || '', type: data.documentType || '', fields });
      FIELDS.forEach((f) => { if (!profile[f] && fields[f]) profile[f] = fields[f]; });
    } catch { /* skip a document that cannot be read */ }
  }
  return { profile, docs, key };
}

const toB64 = (bytes) => Buffer.from(bytes).toString('base64');

// Encrypts a value the way the browser does (encryption.ts), so the app can read it later.
async function encryptPayload(value, key, saltB64) {
  const plain = value instanceof Uint8Array ? value : Buffer.from(typeof value === 'object' ? JSON.stringify(value) : String(value), 'utf8');
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, plain);
  return { v: 'formos_v2_aes_gcm_pbkdf2', iv: toB64(iv), salt: saltB64, kdfParams: { iterations: KDF.iterations, hash: KDF.hash }, ct: toB64(new Uint8Array(ct)) };
}

// Builds the encrypted file envelope the browser builds (fileEncryption.ts): a length-prefixed JSON header that
// is authenticated with the file, then AES-GCM over [filename length][filename][file bytes].
async function encryptFileEnvelope(fileBuffer, key, saltB64, filename, mimeType) {
  const nameBytes = Buffer.from(filename, 'utf8');
  const plain = Buffer.alloc(2 + nameBytes.length + fileBuffer.length);
  plain.writeUInt16BE(nameBytes.length, 0);
  nameBytes.copy(plain, 2);
  fileBuffer.copy(plain, 2 + nameBytes.length);

  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const header = Buffer.from(JSON.stringify({
    v: 'formos_v2_file_aes_gcm', encryptionVersion: 1, algorithm: 'AES-GCM',
    iv: toB64(iv), salt: saltB64, kdfParams: { iterations: KDF.iterations, hash: KDF.hash }, mimeType,
  }), 'utf8');
  const ct = Buffer.from(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: header, tagLength: 128 }, key, plain));
  const envelope = Buffer.alloc(4 + header.length + ct.length);
  envelope.writeUInt32BE(header.length, 0);
  header.copy(envelope, 4);
  ct.copy(envelope, 4 + header.length);
  return envelope;
}

// Opens a file envelope built by the app or by encryptFileEnvelope. Returns the original bytes and file name.
async function decryptFileEnvelope(envelope, key) {
  if (envelope.length < 4) throw new Error('Invalid file envelope');
  const headerLength = envelope.readUInt32BE(0);
  if (envelope.length < 4 + headerLength) throw new Error('Invalid file envelope');
  const headerBytes = envelope.subarray(4, 4 + headerLength);
  const header = JSON.parse(headerBytes.toString('utf8'));
  if (header.v !== 'formos_v2_file_aes_gcm') throw new Error('Unsupported file envelope');
  const plain = Buffer.from(await subtle.decrypt({ name: 'AES-GCM', iv: b64(header.iv), additionalData: headerBytes, tagLength: 128 }, key, envelope.subarray(4 + headerLength)));
  const nameLength = plain.readUInt16BE(0);
  return { bytes: plain.subarray(2 + nameLength), filename: plain.subarray(2, 2 + nameLength).toString('utf8'), mimeType: header.mimeType };
}

module.exports = { openVault, unlockDataKey, decryptPayload, encryptPayload, encryptFileEnvelope, decryptFileEnvelope };
