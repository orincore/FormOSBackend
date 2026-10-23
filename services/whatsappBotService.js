const User = require('../models/User');
const Document = require('../models/Document');
const { serializedId } = require('./whatsappPatches');
const { limitTo, documentDetailsFor, requestedFields, wantsEverything } = require('./whatsappFields');
const docFields = require('./documentFields');
const docKind = require('./whatsappDocKind');
const ragService = require('./ragService');
const aiService = require('./aiService');
const { savePlainDocument } = require('../controllers/documentController');
const { buildPreview } = require('./documentPreview');
const { evaluateEligibility, ageFrom } = require('../controllers/eligibilityController');
const { openVault, encryptPayload, encryptFileEnvelope } = require('./vaultCrypto');
const agent = require('./whatsappAgent');
const StorageService = require('./storageService');
const ocrService = require('./ocrService');

const MAX_FILE_BYTES = parseInt(process.env.MAX_FILE_SIZE, 10) || 10 * 1024 * 1024;
// Any file is stored as sent. Only these are read for details (OCR); the rest are kept and can be sent back.
const OCR_TYPES = ['image/jpeg', 'image/png', 'application/pdf'];
const EXT_BY_MIME = {
  'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/heic': 'heic', 'image/heif': 'heif', 'image/gif': 'gif',
  'application/pdf': 'pdf', 'application/msword': 'doc', 'text/plain': 'txt',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
  'application/vnd.ms-excel': 'xls', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
};
const MIME_BY_EXT = { jpg: 'image/jpeg', jpeg: 'image/jpeg', jpe: 'image/jpeg', png: 'image/png', webp: 'image/webp', heic: 'image/heic', heif: 'image/heif', gif: 'image/gif', pdf: 'application/pdf', doc: 'application/msword', docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', xls: 'application/vnd.ms-excel', xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', txt: 'text/plain' };

// The type WhatsApp reports is unreliable (image/jpg, octet-stream, none), so the file's own first bytes decide.
function sniffMime(buffer) {
  if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return 'image/jpeg';
  if (buffer.length >= 8 && buffer.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
  if (buffer.length >= 5 && buffer.subarray(0, 5).toString('latin1') === '%PDF-') return 'application/pdf';
  if (buffer.length >= 12 && buffer.subarray(0, 4).toString('latin1') === 'RIFF' && buffer.subarray(8, 12).toString('latin1') === 'WEBP') return 'image/webp';
  if (buffer.length >= 12 && buffer.subarray(4, 8).toString('latin1') === 'ftyp' && /^(heic|heix|mif1|msf1|heif)/.test(buffer.subarray(8, 12).toString('latin1'))) return 'image/heic';
  return null;
}
const MAX_REPLY = 3800;
const PER_MINUTE = 15;
const READ_WAIT_MS = 45000;
const STALE_MESSAGE_S = 120;

const TYPE_LABEL = { aadhaar: 'Aadhaar card', pan: 'PAN card', passport: 'Passport', license: 'Driving licence', marriage: 'Marriage certificate', birth: 'Birth certificate', voter: 'Voter ID card', vehicle: 'Vehicle registration (RC)', marksheet: 'Marksheet', certificate: 'Certificate', bank: 'Bank document', insurance: 'Insurance document', other: 'Document' };

const HELP = `*FormOS assistant*
Just tell me what you want, in your own words. For example:

*Save*: send a photo or PDF of a document, or say "save my phone number 9876543210"
*Find*: "what is my date of birth?", "list my documents", "which document has my father's name?"
*Get a file back*: "send me my PAN card" (I ask for your 6-digit PIN first)
*Full numbers*: say *full* to see complete Aadhaar and PAN (PIN needed)
*Manage*: "rename document 2 to Passport", "delete my old PAN" (I ask you to confirm)
*Forms*: "what do I type in a form asking name, DOB and Aadhaar?"
*Eligibility*: "am I eligible for the PM Kisan scheme?"
*lock*: hide details again. *unlink*: stop using this number.

Aadhaar and PAN are masked, and files stay private, until you confirm your PIN.`;

// The AI writes Markdown; WhatsApp has its own: *bold*, _italic_, no headings, no tables.
const toWhatsApp = (text) => String(text)
  .replace(/^#{1,6}\s*(.+)$/gm, '*$1*')
  .replace(/\*\*(.+?)\*\*/g, '*$1*')
  .replace(/__(.+?)__/g, '*$1*')
  .replace(/^\s*[-*]\s+/gm, '- ')
  .replace(/\[([^\]]+)\]\((https?:[^)]+)\)/g, '$1 ($2)')
  .replace(/\u2011/g, '-');
const clip = (text) => {
  const plain = toWhatsApp(text);
  return plain.length > MAX_REPLY ? `${plain.slice(0, MAX_REPLY)}...` : plain;
};
const maskTail = (value) => (value && value.length > 4 ? `****${value.slice(-4)}` : value);

// Per-sender memory for rate limits and one-off notices. It is small and resets on restart.
const hits = new Map();
const notices = new Map();

function tooFast(key) {
  const now = Date.now();
  const recent = (hits.get(key) || []).filter((t) => now - t < 60000);
  recent.push(now);
  hits.set(key, recent);
  return recent.length > PER_MINUTE;
}

function onceEvery(key, ms) {
  const now = Date.now();
  if (now - (notices.get(key) || 0) < ms) return false;
  notices.set(key, now);
  if (notices.size > 5000) notices.delete(notices.keys().next().value);
  return true;
}

// ---- Full (unmasked) details: confirmed with the member's FormOS PIN -----------------------------------
const PIN_WAIT_MS = 3 * 60 * 1000;
// Once the PIN is confirmed, full details stay available until the member sends "lock" (or the server restarts,
// or they switch the setting off). Set WHATSAPP_UNLOCK_MINUTES to add an automatic limit.
const UNLOCK_MINUTES = Number(process.env.WHATSAPP_UNLOCK_MINUTES) || 0;
const unlockEnds = () => (UNLOCK_MINUTES > 0 ? Date.now() + UNLOCK_MINUTES * 60 * 1000 : Infinity);
const MAX_PIN_FAILS = 5;
const PIN_LOCK_MS = 15 * 60 * 1000;
const awaitingPin = new Map(); // userId -> { question, expiresAt }
const awaitingKind = new Map(); // userId -> { documentId, v2, guess, awaiting: 'confirm' | 'type', expiresAt }: an upload whose kind was asked about
const KIND_WAIT_MS = 10 * 60 * 1000;
const revealUntil = new Map(); // userId -> time the unmasked window ends
const vaults = new Map(); // userId -> { data: { profile, docs }, until }: a Security V2 vault opened with the PIN, in memory only
const lastQuestion = new Map(); // userId -> { text, at }, so a bare "full" knows what to show

const FULL_WORD = /\b(full|complete|entire|unmask\w*|reveal|actual|whole|exact|unhide)\b/i;
const SENSITIVE_THING = /\b(aadhaa?r|aadhar|adhar|pan|number|details?|documents?|docs|data|profile|info\w*|everything|passport|licen[cs]e)\b/i;
const asksForFull = (raw) => { const text = String(raw).replace(/\b(full|complete)[ -]?(name|address|postal address)\b/gi, ' '); return asksForFullPlain(text); };
const asksForFullPlain = (text) => (FULL_WORD.test(text) && SENSITIVE_THING.test(text))
  || /^\s*(?:show\s+|give\s+me\s+)?(?:it\s+)?(?:full|unmask|reveal|complete)(?:\s+(?:it|details?|number|info))?\s*[.!?]?\s*$/i.test(text);

const revealActive = (userId) => {
  const until = revealUntil.get(String(userId));
  if (until && until > Date.now()) return true;
  revealUntil.delete(String(userId));
  return false;
};

const FIELD_LABEL = {
  fullName: 'Name', fatherName: "Father's name", dateOfBirth: 'Date of birth', gender: 'Gender',
  aadhaarNumber: 'Aadhaar', panNumber: 'PAN', passportNumber: 'Passport', drivingLicenseNumber: 'Licence',
  address: 'Address', pincode: 'PIN code', state: 'State', phone: 'Phone', email: 'Email',
};
const spaced = (aadhaar) => String(aadhaar).replace(/(\d{4})(?=\d)/g, '$1 ');
const formatField = (key, value) => (key === 'aadhaarNumber' ? spaced(value) : value);

// Everything stored, unmasked: the profile first, then what was read from each document.
async function fullDetailsText(user) {
  const profile = user.extractedData || {};
  const lines = [];
  const base = { fullName: profile.fullName || user.name, email: profile.email || user.email, phone: profile.phone || user.phone, ...profile };
  Object.keys(FIELD_LABEL).forEach((key) => { if (base[key]) lines.push(`*${FIELD_LABEL[key]}*: ${formatField(key, base[key])}`); });
  const out = [lines.length ? `*Your details*\n${lines.join('\n')}` : 'I have no profile details saved yet.'];

  const docs = await Document.find({ userId: user._id, securityVersion: { $ne: 2 }, ocrStatus: 'completed' }).sort({ uploadedAt: -1 }).limit(8).select('originalName documentType structuredData').lean();
  docs.forEach((doc) => {
    const rows = Object.keys(FIELD_LABEL).filter((k) => doc.structuredData?.[k]).map((k) => `${FIELD_LABEL[k]}: ${formatField(k, doc.structuredData[k])}`);
    if (rows.length) out.push(`*${TYPE_LABEL[doc.documentType] || 'Document'}* (${doc.originalName})\n${rows.join('\n')}`);
  });
  return out.join('\n\n');
}

const PERSONAL = /\b(my|mine)\b[\s\S]*\b(name|dob|birth|age|address|phone|mobile|email|aadhaa?r|aadhar|adhar|pan|passport|licen[cs]e|details?|documents?|docs|profile|info\w*|number|father|gender)\b|\b(what|show|tell|give|send)\b[\s\S]*\b(aadhaa?r|aadhar|pan|passport|licen[cs]e)\b/i;
const asksPersonal = (text) => PERSONAL.test(text);

const vaultEntry = (id) => {
  const v = vaults.get(String(id));
  if (v && v.until > Date.now()) return v;
  vaults.delete(String(id));
  return null;
};
const vaultFor = (id) => vaultEntry(id)?.data || null;
const closeVault = (id) => { vaults.delete(String(id)); };

const SITE_URL = () => (process.env.FRONTEND_URL || 'https://formos.online').replace(/\/$/, '');
const ENCRYPTED_OFF = () => `Your account encrypts documents on your own device, so by default I cannot read them here.\n\nTo let me open them with your PIN, turn on *Read my encrypted details on WhatsApp* at ${SITE_URL()}/dashboard/whatsapp. I will ask for your PIN, and your details stay open until you send *lock*.`;

// Everything a member has, unmasked, as WhatsApp text. Used for an opened Security V2 vault (decrypted in memory).
function formatDetails(profile, docs) {
  const lines = Object.keys(FIELD_LABEL).filter((k) => profile[k]).map((k) => `*${FIELD_LABEL[k]}*: ${formatField(k, profile[k])}`);
  const out = [lines.length ? `*Your details*\n${lines.join('\n')}` : 'I have no profile details saved yet.'];
  docs.forEach((doc) => {
    const rows = Object.keys(FIELD_LABEL).filter((k) => doc.fields?.[k]).map((k) => `${FIELD_LABEL[k]}: ${formatField(k, doc.fields[k])}`);
    if (rows.length) out.push(`*${TYPE_LABEL[doc.type] || 'Document'}* (${doc.name})\n${rows.join('\n')}`);
  });
  return out.join('\n\n');
}

const SPECIFIC = [
  [/\bpassport\b/i, 'passportNumber'], [/\blicen[cs]e\b/i, 'drivingLicenseNumber'], [/\bfather\b/i, 'fatherName'],
  [/\bgender\b|\bsex\b/i, 'gender'], [/\bpin ?code\b|\bpostal\b/i, 'pincode'], [/\bstate\b/i, 'state'],
];

// Answers from an opened vault without any cloud AI: the decrypted data never leaves this process.
function answerFromVault(text, vault) {
  const { profile, docs } = vault;
  // A specific question gets only that detail (read from the profile, or from the document named).
  const asked = limitTo(text);
  if (asked && !documentDetailsFor(text)) {
    const { doc } = requestedFields(text);
    const pool = doc ? docs.filter((d) => d.type === doc) : docs;
    const rows = []; const missing = [];
    for (const key of asked) {
      const value = (doc ? null : profile[key]) || pool.find((d) => d.fields?.[key])?.fields?.[key];
      if (value) rows.push(`*${FIELD_LABEL[key]}*: ${formatField(key, value)}`); else missing.push(FIELD_LABEL[key].toLowerCase());
    }
    return [...rows, ...(missing.length ? [`I do not have your ${missing.join(' or ')} in your vault.`] : [])].join('\n');
  }
  for (const [pattern, key] of SPECIFIC) {
    if (pattern.test(text)) return profile[key] ? `*${FIELD_LABEL[key]}*: ${formatField(key, profile[key])}` : `I do not have your ${FIELD_LABEL[key].toLowerCase()} in your vault.`;
  }
  // Anything else specific is looked up in the documents' own fields (any labels they print), locally.
  if (!wantsEverything(text)) {
    const pool = [...docs.map((d) => ({ name: d.name, title: d.title || '', type: d.type, fields: d.fields || {} })), { name: 'Your profile', title: 'Your profile', type: '', fields: Object.fromEntries(Object.entries(profile).filter(([k, v]) => FIELD_LABEL[k] && typeof v === 'string' && v)) }];
    const found = docFields.searchFields(text, pool);
    if (found.length) return docFields.formatMatches(found, { reveal: true });
  }
  const direct = ragService.getDirectAnswer(text, { name: profile.fullName, email: profile.email, phone: profile.phone, extractedData: profile, securityVersion: 1 }, { reveal: true });
  const wantsAll = /\b(details?|everything|profile|info\w*|all)\b/i.test(text);
  if (direct && !wantsAll) return direct;
  if (/\b(documents?|docs|files)\b/i.test(text) && !wantsAll) {
    return docs.length ? `*Your documents*\n${docs.map((d, i) => `${i + 1}. ${d.name}${d.type ? ` (${TYPE_LABEL[d.type] || 'Document'})` : ''}`).join('\n')}` : 'Your vault has no documents yet.';
  }
  if (wantsAll) return formatDetails(profile, docs);
  return direct || 'I can show your details, a specific number such as your Aadhaar or PAN, or list your documents. What would you like to see?';
}

// Only coarse facts ever go to the cloud AI for an eligibility check: never names, numbers or addresses.
const v2Facts = (vault) => {
  const addr = vault.profile.address || '';
  const state = vault.profile.state || (addr.match(/\b(Maharashtra|Gujarat|Karnataka|Tamil Nadu|Delhi|Rajasthan|Uttar Pradesh|Madhya Pradesh|West Bengal|Punjab|Haryana|Bihar|Odisha|Kerala|Assam|Telangana|Andhra Pradesh|Goa)\b/i) || [])[0] || '';
  const city = (addr.match(/\b(Mumbai|Delhi|Bengaluru|Bangalore|Chennai|Kolkata|Hyderabad|Pune|Ahmedabad|Jaipur|Lucknow|Surat|Nagpur|Indore|Thane)\b/i) || [])[0] || '';
  const held = new Set();
  vault.docs.forEach((d) => { if (d.type && TYPE_LABEL[d.type] && d.type !== 'other') held.add(TYPE_LABEL[d.type]); });
  if (vault.profile.aadhaarNumber) held.add('Aadhaar card');
  if (vault.profile.panNumber) held.add('PAN card');
  if (vault.profile.passportNumber) held.add('Passport');
  return { age: ageFrom(vault.profile.dateOfBirth), state, city, documents: [...held] };
};

// Deleting is best effort: WhatsApp only lets an account remove its own messages for everyone.
async function removePinMessage(msg) {
  try { await msg.delete(true); } catch { try { await msg.delete(false); } catch { /* the member can delete it */ } }
}

async function askForPin(msg, user, question, media = null) {
  awaitingPin.set(String(user._id), { question, media, expiresAt: Date.now() + PIN_WAIT_MS });
  await msg.reply('To show the full numbers I need to check it is you. Reply with your *6-digit FormOS PIN* within 3 minutes.\n\nAnyone who can see this chat can see your reply, so delete the message afterwards. Reply *cancel* to stop.');
}

// Returns the text to send back after a PIN message. Never logs, stores or forwards the PIN.
async function checkPin(msg, user, pin) {
  const id = String(user._id);
  const pending = awaitingPin.get(id);
  awaitingPin.delete(id);
  await removePinMessage(msg);

  const fresh = await User.findById(user._id);
  const lockedUntil = fresh.whatsapp?.pinLockedUntil;
  if (lockedUntil && lockedUntil > new Date()) {
    return `Too many wrong PINs. Full details are locked for ${Math.ceil((lockedUntil - Date.now()) / 60000)} more minutes. Masked answers still work.`;
  }

  if (!(await fresh.comparePin(pin))) {
    const after = await User.findOneAndUpdate({ _id: user._id }, { $inc: { 'whatsapp.pinFailures': 1 } }, { new: true });
    const failures = after?.whatsapp?.pinFailures || 1;
    if (failures >= MAX_PIN_FAILS) {
      await User.updateOne({ _id: user._id }, { $set: { 'whatsapp.pinFailures': 0, 'whatsapp.pinLockedUntil': new Date(Date.now() + PIN_LOCK_MS) } });
      return 'That PIN is not right, and there were too many wrong tries. Full details are locked for 15 minutes. Masked answers still work.';
    }
    awaitingPin.set(id, { question: pending?.question || 'show my full details', media: pending?.media, expiresAt: Date.now() + PIN_WAIT_MS });
    const left = MAX_PIN_FAILS - failures;
    return `That PIN is not right. ${left} ${left === 1 ? 'try' : 'tries'} left. Send it again, or reply *cancel*.`;
  }

  if (fresh.securityVersion === 2) {
    if (!fresh.whatsapp?.allowEncryptedAccess) return ENCRYPTED_OFF();
    try {
      const opened = await openVault(fresh, pin);
      vaults.set(id, { data: { profile: opened.profile, docs: opened.docs }, key: opened.key, salt: fresh.userSalt, until: unlockEnds() });
      if (UNLOCK_MINUTES > 0) {
        const timer = setTimeout(() => vaults.delete(id), UNLOCK_MINUTES * 60 * 1000 + 1000);
        if (timer.unref) timer.unref();
      }
    } catch (error) {
      console.error('[whatsapp] could not open an encrypted vault:', error.code || error.message);
      return 'Your PIN is right, but I could not open your encrypted vault with it. Please open the FormOS app once, unlock your vault there, and try again.';
    }
  }
  await User.updateOne({ _id: user._id }, { $set: { 'whatsapp.pinFailures': 0, 'whatsapp.pinLockedUntil': null } });
  revealUntil.set(id, unlockEnds());
  return { ok: true, question: pending?.question || 'show my full details', media: pending?.media || null };
}

// WhatsApp Web sometimes fails or returns nothing the first time a file is fetched (the media is not ready yet, or
// WhatsApp changed its page). Try again a few times, once with a freshly fetched copy of the message.
async function fetchMedia(msg, wa) {
  let lastError = null;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const target = attempt === 1 ? msg : (await wa?.client?.getMessageById?.(serializedId(msg.id)).catch(() => null)) || msg;
      const media = await target.downloadMedia();
      if (media && media.data) return media;
      lastError = new Error('WhatsApp returned no file data');
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 1200 * attempt));
  }
  throw lastError;
}

// Downloads and checks a file sent in the chat. Replies with the reason and returns null when it cannot be used.
async function readMedia(msg, wa) {
  let media;
  try {
    media = await fetchMedia(msg, wa);
  } catch (error) {
    const detail = `${error?.name || 'Error'}: ${String(error?.message ?? error).slice(0, 200)}`;
    console.error(`[whatsapp] could not download a file from WhatsApp (${detail})`);
    if (wa?.stats) { wa.stats.failed += 1; wa.stats.lastError = `File download failed: ${detail}`.slice(0, 200); }
    await msg.reply('I could not download that file from WhatsApp. Please send it again. If it keeps failing, attach it as a document (paperclip, then Document) instead of a photo.');
    return null;
  }
  const buffer = Buffer.from(media.data, 'base64');
  if (!buffer.length) { await msg.reply('That file arrived empty. Please send it again.'); return null; }
  if (buffer.length > MAX_FILE_BYTES) { await msg.reply(`That file is larger than ${Math.round(MAX_FILE_BYTES / 1048576)} MB. Please send a smaller one.`); return null; }
  const reported = String(media.mimetype || '').split(';')[0].trim().toLowerCase().replace('image/jpg', 'image/jpeg');
  const nameExt = String(media.filename || '').split('.').pop().toLowerCase();
  const generic = !reported || reported === 'application/octet-stream';
  const mimeType = sniffMime(buffer) || (generic ? MIME_BY_EXT[nameExt] : reported) || 'application/octet-stream';
  const ext = EXT_BY_MIME[mimeType] || (/^[a-z0-9]{1,5}$/.test(nameExt) && media.filename ? nameExt : 'bin');
  const base = (media.filename || `whatsapp-${Date.now()}.${ext}`).replace(/[^\w.\- ]/g, '_').slice(0, 120);
  const originalName = base.toLowerCase().endsWith(`.${ext}`) ? base : `${base}.${ext}`;
  return { buffer, mimeType, originalName, ocr: OCR_TYPES.includes(mimeType) };
}

// Saves a file for a Security V2 member: it is read in memory, encrypted with their own vault key in the same
// format the app uses, and only the encrypted copy is stored (in R2). Nothing readable touches the disk, and the
// text read from it is never sent to the cloud AI.
async function saveEncryptedMedia(msg, user, entry, file) {
  await msg.reply(file.ocr
    ? 'Got it. Encrypting your document into your vault and reading it now, this takes a few seconds.'
    : 'Got it. Encrypting your file into your vault now.');

  // The file is encrypted and stored first, so a failure while reading it can never lose it.
  const envelope = await encryptFileEnvelope(file.buffer, entry.key, entry.salt, file.originalName, file.mimeType);
  const stored = await StorageService.uploadEncrypted(envelope, file.mimeType, user._id);
  let text = '';
  let found = {};
  if (file.ocr) {
    try {
      // Local reader only: the document's text never leaves this server. The page layout gives the other fields too.
      const read = await ocrService.readBuffer(file.buffer, file.mimeType);
      text = read.text;
      found = text ? ocrService.parseStructuredData(text) : {};
      const extra = await docFields.extractFields({ text, items: read.items, known: found, typeLabel: TYPE_LABEL[found.documentType] || '', fileName: file.originalName });
      found = docFields.assembleStructured({ known: found, fields: extra.fields, documentTitle: extra.documentTitle });
    } catch (error) {
      console.error(`[whatsapp] could not read a saved file (${error?.message}); it is stored anyway`);
    }
  }
  const metadata = { ...found, documentName: file.originalName, originalName: file.originalName, fileSize: `${(file.buffer.length / 1024).toFixed(1)} KB`, securityLevel: 'V2 Client-Side Encrypted' };
  let created;
  try {
    created = await Document.create({
      userId: user._id,
      filename: 'Encrypted File',
      originalName: 'encrypted_file',
      filePath: stored.filePath,
      fileSize: envelope.length,
      mimeType: file.mimeType,
      documentType: 'other',
      ocrStatus: 'completed',
      storageType: stored.storageType,
      gridfsId: stored.gridfsId,
      s3Key: stored.s3Key,
      securityVersion: 2,
      encryptionVersion: 1,
      encryptedText: JSON.stringify(await encryptPayload(text || `Document: ${file.originalName}`, entry.key, entry.salt)),
      encryptedStructuredData: JSON.stringify(await encryptPayload(metadata, entry.key, entry.salt)),
    });
  } catch (error) {
    await StorageService.discardEncrypted(stored).catch(() => {});
    throw error;
  }

  // The open vault learns about the new document right away.
  const fields = {};
  Object.keys(FIELD_LABEL).forEach((k) => { if (found[k]) fields[k] = found[k]; });
  const allFields = Object.fromEntries(Object.entries(found).filter(([k, v]) => !docFields.HIDDEN_KEYS.has(k) && typeof v === 'string' && v));
  entry.data.docs.unshift({ id: String(created._id), name: file.originalName, title: found.documentTitle || '', type: found.documentType || '', fields: { ...fields, ...allFields } });
  Object.keys(fields).forEach((k) => { if (!entry.data.profile[k]) entry.data.profile[k] = fields[k]; });

  const rows = [['Type', TYPE_LABEL[found.documentType]], ...Object.keys(FIELD_LABEL).filter((k) => found[k]).map((k) => [FIELD_LABEL[k], formatField(k, found[k])])].filter(([, v]) => v);
  const guess = docKind.guessKind({ documentType: found.documentType, documentTitle: found.documentTitle, text });
  const question = askKind(user._id, created._id, true, file.ocr ? guess : null);
  if (!file.ocr) return `Saved *${file.originalName}* and encrypted it in your vault. Ask me to send it back any time.\n\n${question}`;
  if (!rows.length) return `Saved and encrypted in your vault. I could not read any details from it, but the file is safe and you can ask me to send it back. A clearer photo usually reads better.\n\n${question}`;
  return `Saved${guess ? ` as a *${guess.label}*` : ''} and encrypted in your vault. Here is what I read:\n\n${rows.map(([k, v]) => `*${k}*: ${v}`).join('\n')}\n\nIf a detail is wrong, you can correct it in the app under Documents.\n\n${question}`;
}

// ---- confirming what kind of document an upload is -----------------------------------------------------------------
// After a file is saved the assistant says what it thinks it is and asks the member to confirm; their answer ("yes", "no",
// "it is my PAN card") sets the type. Without an answer the guess simply stays.
function askKind(userId, documentId, v2, guess) {
  awaitingKind.set(String(userId), { documentId: String(documentId), v2, guess, awaiting: guess ? 'confirm' : 'type', expiresAt: Date.now() + KIND_WAIT_MS });
  if (awaitingKind.size > 2000) awaitingKind.delete(awaitingKind.keys().next().value);
  return docKind.confirmQuestion(guess);
}

const TOP_LEVEL_TYPES = new Set(['aadhaar', 'pan', 'passport', 'license']);

// Saves the kind on the document. A corrected kind also renames it; a confirmed guess keeps its richer printed title.
async function applyKind(user, pending, kind, { changed }) {
  const set = { 'structuredData.documentType': kind.key, typeConfirmedAt: new Date(), documentType: TOP_LEVEL_TYPES.has(kind.key) ? kind.key : 'other' };
  if (changed) set['structuredData.documentTitle'] = kind.label;
  if (!pending.v2) {
    await Document.updateOne({ _id: pending.documentId, userId: user._id }, { $set: set });
    return true;
  }
  // An encrypted document's details are inside its encrypted record: open it with the vault key, change it, seal it again.
  const entry = vaultEntry(String(user._id));
  if (!entry) return false;
  const row = await Document.findOne({ _id: pending.documentId, userId: user._id, securityVersion: 2 }).select('encryptedStructuredData');
  if (!row?.encryptedStructuredData) return false;
  const data = await decryptPayload(row.encryptedStructuredData, entry.key);
  if (!data || typeof data !== 'object') return false;
  data.documentType = kind.key;
  if (changed) data.documentTitle = kind.label;
  await Document.updateOne({ _id: pending.documentId, userId: user._id }, { $set: { encryptedStructuredData: JSON.stringify(await encryptPayload(data, entry.key, entry.salt)), typeConfirmedAt: new Date(), documentType: set.documentType } });
  const held = entry.data.docs.find((d) => d.id === pending.documentId);
  if (held) { held.type = kind.key; if (changed) held.title = kind.label; }
  return true;
}

// Reads the member's answer to "is that correct?". Returns true when the message was an answer (and was handled).
async function handleKindReply(msg, user, text) {
  const id = String(user._id);
  const pending = awaitingKind.get(id);
  if (!pending) return false;
  if (pending.expiresAt <= Date.now()) { awaitingKind.delete(id); return false; }

  const finish = async (kind, changed, lead) => {
    awaitingKind.delete(id);
    const ok = await applyKind(user, pending, kind, { changed }).catch((error) => { console.error(`[whatsapp] could not save the document kind: ${error.message}`); return false; });
    await msg.reply(ok ? `${lead} *${kind.label}*.` : `Thanks. I could not update it just now, so I kept my first guess. You can change it in the app under Documents.`);
    return true;
  };

  if (docKind.YES.test(text)) {
    if (pending.guess) return finish(pending.guess, false, 'Great, it is saved as your');
    await msg.reply(`What kind of document is it? (for example ${docKind.EXAMPLES})`);
    return true;
  }
  if (docKind.NO.test(text)) {
    pending.awaiting = 'type';
    pending.expiresAt = Date.now() + KIND_WAIT_MS;
    await msg.reply(`Okay, what kind of document is it? (for example ${docKind.EXAMPLES})`);
    return true;
  }
  const named = docKind.kindFromText(text);
  if (named && text.length <= 60) return finish(named, !pending.guess || named.key !== pending.guess.key, 'Thanks, I saved it as your');
  if (pending.awaiting === 'type') {
    const label = docKind.customLabel(text);
    if (label) return finish({ key: 'other', label }, true, 'Okay, I saved it as');
  }
  awaitingKind.delete(id); // they moved on to something else; the guess stays and the message is handled normally
  return false;
}

async function typing(msg) {
  try { (await msg.getChat()).sendStateTyping(); } catch { /* cosmetic only */ }
}

function formatEligibility(r) {
  const lines = [`*${r.opportunityType}*`, `Match: *${r.matchScore}%*  ${r.isEligible ? 'You look eligible.' : 'Not eligible yet.'}`];
  if (r.reasoning) lines.push('', r.reasoning);
  if (r.strengths.length) lines.push('', '*What matches*', ...r.strengths.map((s) => `+ ${s}`));
  if (r.missingRequirements.length) {
    lines.push('', '*What to fix*');
    r.missingRequirements.forEach((m, i) => lines.push(`${i + 1}. ${m.requirement}${m.suggestion ? `\n   Next step: ${m.suggestion}` : ''}`));
  }
  return lines.join('\n');
}

async function describeUpload(documentId, reveal = false, userId = null) {
  const ask = (guess) => (userId ? `\n\n${askKind(userId, documentId, false, guess)}` : '');
  const deadline = Date.now() + READ_WAIT_MS;
  let doc;
  while (Date.now() < deadline) {
    doc = await Document.findById(documentId).lean();
    if (doc && ['completed', 'failed'].includes(doc.ocrStatus)) break;
    await new Promise((resolve) => setTimeout(resolve, 2500));
  }
  if (!doc || doc.ocrStatus === 'failed') return `I saved the file, and you can ask me to send it back, but I could not read any text from it. A clearer photo or a PDF usually works better.${ask(null)}`;
  if (doc.ocrStatus !== 'completed') return `I saved the file and I am still reading it. Ask "documents" in a minute to see it.${ask(null)}`;

  const d = docFields.cleanKnown(doc.structuredData || {});
  // The AI already named and summarised the document when it was read: that is what the member is told. The question below
  // only asks them to correct it when the AI could not tell what it was.
  const preview = buildPreview(doc);
  const sure = preview.kind !== 'other' || Boolean(d.documentTitle);
  const guess = sure ? { key: preview.kind, label: d.documentTitle || preview.kindLabel } : null;
  const rows = [
    ['Type', guess ? guess.label : (TYPE_LABEL[d.documentType] || TYPE_LABEL[doc.documentType])],
    ['Name', d.fullName], ['Date of birth', d.dateOfBirth], ['Gender', d.gender],
    ['Aadhaar', reveal && d.aadhaarNumber ? spaced(d.aadhaarNumber) : maskTail(d.aadhaarNumber)], ['PAN', reveal ? d.panNumber : maskTail(d.panNumber)],
    ['Address', d.address],
  ].filter(([, v]) => v);
  if (!rows.length) return `I saved the file, but could not find any details in it. A clearer photo or a PDF usually works better.${ask(guess)}`;
  const extras = preview.facts.map((f) => [f.label, f.value]);
  const tail = sure ? '' : ask(guess);
  return `Saved${guess ? ` as *${guess.label}*` : ''}.${d.documentSummary ? `\n${d.documentSummary}` : ''}\n\n${[...rows, ...extras].map(([k, v]) => `*${k}*: ${v}`).join('\n')}\n\nEverything on it is saved, so you can ask me anything about it. If a detail is wrong, you can correct it in the app under Documents.${tail}`;
}

async function listDocuments(user) {
  const docs = await Document.find({ userId: user._id }).sort({ uploadedAt: -1 }).limit(15).select('originalName documentType ocrStatus securityVersion uploadedAt structuredData.documentTitle structuredData.documentType').lean();
  if (!docs.length) return 'You have no documents stored yet. Send me a photo or PDF of one and I will save it.';
  const lines = docs.map((d, i) => {
    const named = d.securityVersion === 2 ? 'Encrypted document' : /^whatsapp-\d+\.\w+$/i.test(d.originalName || '') ? '' : d.originalName;
    const state = d.ocrStatus === 'completed' ? 'read' : d.ocrStatus === 'failed' ? 'could not be read' : 'being read';
    const kind = d.securityVersion === 2 ? (TYPE_LABEL[d.documentType] || 'Document') : (d.structuredData?.documentTitle || TYPE_LABEL[d.structuredData?.documentType] || TYPE_LABEL[d.documentType] || 'Document');
    // What it is comes first. The file name only helps when it says something (a photo from WhatsApp is just a number).
    return `${i + 1}. ${kind}${named && named !== kind ? ` - ${named}` : ''} (${state})`;
  });
  return `*Your documents*\n${lines.join('\n')}`;
}

// ---- the agent ----------------------------------------------------------------------------------------------------
const history = new Map(); // userId -> recent turns. Holds what was asked and which tools ran, never the details returned.
const pendingActions = new Map(); // userId -> a destructive step waiting for a yes

// Numbers, emails and PANs typed by the member are not kept in the history the AI sees.
const forHistory = (text) => String(text)
  .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '[email]')
  .replace(/\b[A-Za-z]{5}\d{4}[A-Za-z]\b/g, '[id]')
  .replace(/\d[\d\s-]{5,}\d/g, '[number]')
  .replace(/[A-Za-z0-9_-]{15,}/g, '[token]')
  .slice(0, 300);

const agentDeps = {
  get HELP() { return HELP; },
  ENCRYPTED_OFF: () => ENCRYPTED_OFF(),
  answerFromVault: (q, vault) => answerFromVault(q, vault),
  v2Facts: (vault) => v2Facts(vault),
  formatEligibility: (r) => formatEligibility(r),
  setPending: (userId, action) => pendingActions.set(String(userId), { ...action, expiresAt: Date.now() + 2 * 60 * 1000 }),
  lock: (userId) => { const id = String(userId); revealUntil.delete(id); awaitingPin.delete(id); pendingActions.delete(id); history.delete(id); closeVault(id); },
};

async function sendFile(msg, file) {
  const { MessageMedia } = require('whatsapp-web.js');
  const media = new MessageMedia(file.mimeType, file.buffer.toString('base64'), file.filename);
  try {
    await msg.reply(media, undefined, { caption: file.filename });
  } catch (error) {
    // WhatsApp Web sometimes refuses a file sent as an inline photo or video; as a document attachment it goes through.
    console.warn(`[whatsapp] sending ${file.mimeType} inline failed (${String(error?.message ?? error).slice(0, 120)}), sending it as a document`);
    await msg.reply(media, undefined, { caption: file.filename, sendMediaAsDocument: true });
  }
}

// Hands the message to the agent. Returns the text to send, or '' when the answer was already handled here
// (a PIN was asked for). Files the agent produced are sent first.
async function runAgentTurn(msg, user, text) {
  const id = String(user._id);
  await typing(msg);
  const entry = user.securityVersion === 2 ? vaultEntry(id) : null;
  const unlocked = user.securityVersion === 2 ? Boolean(entry) : revealActive(id);
  const recent = (history.get(id) || []).filter((h) => Date.now() - h.at < 30 * 60 * 1000).slice(-6);

  const result = await agent.run({ user, text, history: recent, unlocked, entry, deps: agentDeps });
  if (result.needsPin) { await askForPin(msg, user, text); return ''; }

  for (const file of result.files) await sendFile(msg, file);
  const turns = history.get(id) || [];
  turns.push({ role: 'user', content: forHistory(text), at: Date.now() });
  turns.push({ role: 'assistant', content: result.used.length ? `(I used: ${result.used.join(', ').replace(/_/g, ' ')})` : '(I answered directly)', at: Date.now() });
  history.set(id, turns.slice(-8));
  if (history.size > 2000) history.delete(history.keys().next().value);
  console.log(`[whatsapp] agent handled a request${result.used.length ? ` using ${result.used.join(', ')}` : ' without tools'}`);
  return result.texts.join('\n\n');
}

async function answer(msg, user, text) {
  const lower = text.toLowerCase().trim();
  if (/^(hi|hello|hey|help|menu|start|what can you do\??)\b/.test(lower) && lower.length < 25) return HELP;
  // The plain document list is instant for standard accounts: no AI needed.
  if (user.securityVersion !== 2 && /^(?:show |list |see |my |all )*(?:documents?|docs|files|uploads?)\??$/.test(lower)) return listDocuments(user);

  // Plain questions about one stored detail (name, date of birth, address, Aadhaar, PAN...) are answered straight from
  // the data: instant, exact, and no AI involved. Anything more complex goes to the agent.
  const ONE_DETAIL = /^\s*(?:what(?:'s| is| are)?|show me|tell me|give me|can you tell me|whats)?\s*(?:is\s+)?(?:my|me my)\s+(?:full\s+)?(?:name|e-?mail(?: address| id)?|phone(?: number)?|mobile(?: number| no\.?)?|date of birth|dob|birth ?date|address|aadhaa?r(?: number| no\.?| card number)?|aadhar(?: number)?|pan(?: number| no\.?)?)\s*\??\s*$/i;
  if (ONE_DETAIL.test(text)) {
    const id = String(user._id);
    let direct = null;
    if (user.securityVersion === 2) {
      const vault = vaultFor(id);
      if (vault) direct = ragService.getDirectAnswer(text, { name: vault.profile.fullName, email: vault.profile.email, phone: vault.profile.phone, extractedData: vault.profile, securityVersion: 1 }, { reveal: true });
    } else {
      direct = ragService.getDirectAnswer(text, await User.findById(user._id), { reveal: revealActive(id) });
    }
    if (direct && !/^Name:|^\*Your details/.test(direct)) return direct;
  }
  return runAgentTurn(msg, user, text);
}

const reply = async (msg, text) => { if (text) await msg.reply(clip(text)); };

// Runs a slow step and, if it takes a while, says once that the answer is on its way.
async function withProgress(msg, work) {
  const timer = setTimeout(() => { msg.reply('One moment, I am still working on it.').catch(() => {}); }, 12000);
  try { return await work(); } finally { clearTimeout(timer); }
}

async function handleIncoming(msg, wa) {
  if (!msg || msg.fromMe || msg.isStatus || typeof msg.from !== 'string') return;
  if (msg.from.endsWith('@g.us') || msg.from === 'status@broadcast' || msg.from.endsWith('@newsletter')) return;
  if (msg.timestamp && Date.now() / 1000 - msg.timestamp > STALE_MESSAGE_S) { wa.stats.ignoredOther += 1; return; }

  const stats = wa.stats;
  stats.received += 1;
  stats.lastReceivedAt = Date.now();
  const number = await wa.phoneFor(msg.from, msg);
  if (!number) {
    stats.unresolved += 1;
    console.log('[whatsapp] ignored a message: could not work out the sender\'s phone number');
    return;
  }

  // Only a verified, linked number is ever answered. Anyone else who messages this WhatsApp account
  // (friends, family, strangers) gets no reply at all: the account may be a real person's phone.
  const user = await User.findOne({ 'whatsapp.number': number });
  if (!user) {
    stats.ignoredStranger += 1;
    console.log(`[whatsapp] ignored a message from an unlinked number ending ${number.slice(-4)}`);
    return;
  }

  if (user.status === 'suspended') {
    if (onceEvery(`suspended:${number}`, 6 * 3600 * 1000)) await msg.reply('This FormOS account is suspended. Please contact support.');
    return;
  }

  if (tooFast(`user:${user._id}`)) {
    if (onceEvery(`slow:${user._id}`, 60000)) await msg.reply('You are sending messages faster than I can keep up. Please wait a minute and try again.');
    return;
  }

  try {
    if (msg.hasMedia) {
      const id = String(user._id);
      await typing(msg);
      if (user.securityVersion === 2) {
        if (!user.whatsapp?.allowEncryptedAccess) { await msg.reply(ENCRYPTED_OFF().replace('I cannot read them here', 'I cannot save files here')); return; }
        const file = await readMedia(msg, wa);
        if (!file) return;
        const entry = vaultEntry(id);
        if (!entry) {
          // Hold the file in memory (never on disk) until the PIN arrives.
          await askForPin(msg, user, 'save my file', file);
          return;
        }
        await msg.reply(clip(`${await withProgress(msg, () => saveEncryptedMedia(msg, user, entry, file))}\n\n_Security V2 has been retired. To have the AI read your documents and answer questions about them, open FormOS > Settings and choose *Move to standard storage*._`));
        stats.answered += 1; stats.lastAnsweredAt = Date.now();
        return;
      }
      const file = await readMedia(msg, wa);
      if (!file) return;
      const document = await savePlainDocument({ userId: user._id, buffer: file.buffer, originalName: file.originalName, mimeType: file.mimeType, documentType: 'other', skipOcr: !file.ocr });
      if (!file.ocr) {
        await msg.reply(`Saved *${file.originalName}*. Ask me to send it back any time.\n\n${askKind(user._id, document._id, false, null)}`);
        stats.answered += 1; stats.lastAnsweredAt = Date.now();
        return;
      }
      await msg.reply('Got it. Reading your document now, this takes a few seconds.');
      await msg.reply(clip(await describeUpload(document._id, revealActive(user._id), user._id)));
      stats.answered += 1; stats.lastAnsweredAt = Date.now();
      return;
    }

    const text = String(msg.body || '').trim();
    if (!text) return;

    if (/^unlink$/i.test(text)) {
      agentDeps.lock(user._id);
      await User.updateOne({ _id: user._id }, { $set: { 'whatsapp.number': null, 'whatsapp.verifiedAt': null } });
      await msg.reply('Done. This number is no longer linked to your FormOS account. You can link it again from the app at any time.');
      return;
    }

    const id = String(user._id);

    if (/^lock$/i.test(text)) {
      agentDeps.lock(id);
      await msg.reply('Locked. I am showing masked numbers again.');
      return;
    }

    // The answer to "is that the right kind of document?" after an upload.
    if (awaitingKind.has(id) && await handleKindReply(msg, user, text)) {
      stats.answered += 1; stats.lastAnsweredAt = Date.now();
      return;
    }

    // A destructive step the agent asked about (deleting a document) is carried out by code, only on a plain yes.
    const waiting = pendingActions.get(id);
    if (waiting && waiting.expiresAt <= Date.now()) pendingActions.delete(id);
    if (pendingActions.has(id)) {
      pendingActions.delete(id);
      if (/^(yes|y|yep|yeah|confirm|delete it|sure|do it)$/i.test(text)) {
        const entry = user.securityVersion === 2 ? vaultEntry(id) : null;
        if (!(user.securityVersion === 2 ? entry : revealActive(id))) { await msg.reply('Your session was locked, so I did not delete anything. Ask again and confirm your PIN.'); return; }
        await msg.reply((await agent.executeDelete({ user, entry }, waiting)).text);
        stats.answered += 1; stats.lastAnsweredAt = Date.now();
        return;
      }
      if (/^(no|n|nope|cancel|keep|keep it|stop)$/i.test(text)) { await msg.reply('Okay, I kept it.'); return; }
    }

    // A PIN is only ever read while a request for full details is waiting for it.
    const pending = awaitingPin.get(id);
    if (pending && pending.expiresAt <= Date.now()) awaitingPin.delete(id);
    if (awaitingPin.has(id)) {
      if (/^cancel$/i.test(text)) { awaitingPin.delete(id); await msg.reply('Cancelled. I will keep showing masked numbers.'); return; }
      if (/^\d{6}$/.test(text)) {
        const result = await checkPin(msg, user, text);
        if (typeof result === 'string') { await msg.reply(result); return; }
        await msg.reply(UNLOCK_MINUTES > 0 ? `PIN confirmed. I will show full details for the next ${UNLOCK_MINUTES} minutes. Reply *lock* to hide them sooner.` : 'PIN confirmed. Full details stay visible until you reply *lock*.');
        if (result.media) {
          await msg.reply(clip(await withProgress(msg, () => saveEncryptedMedia(msg, user, vaultEntry(id), result.media))));
          console.log('[whatsapp] saved an encrypted file for a linked member after PIN confirmation');
        } else {
          await reply(msg, await withProgress(msg, () => answer(msg, user, result.question)));
          console.log('[whatsapp] showed full details to a linked member after PIN confirmation');
        }
        stats.answered += 1; stats.lastAnsweredAt = Date.now();
        return;
      }
      if (/^\d{4,8}$/.test(text)) { await msg.reply('Your FormOS PIN has 6 digits. Send it again, or reply *cancel*.'); return; }
      awaitingPin.delete(id); // they asked something else, so the PIN request is dropped
    } else if (/^\d{6}$/.test(text)) {
      // Never pass a bare 6-digit message on to the AI: it may be a PIN sent by mistake.
      await removePinMessage(msg);
      await msg.reply('I was not waiting for a PIN, so I ignored that. If you want full details, send *full* first.');
      return;
    }

    if (user.securityVersion === 2 && (asksForFull(text) || asksPersonal(text)) && !/\beligib/i.test(text)) {
      if (!user.whatsapp?.allowEncryptedAccess) { await msg.reply(ENCRYPTED_OFF()); return; }
      const vault = vaultFor(id);
      if (!vault) {
        const last = lastQuestion.get(id);
        const bare = /^\s*(?:show\s+|give\s+me\s+)?(?:it\s+)?(?:full|unmask|reveal|complete)(?:\s+(?:it|details?|number|info))?\s*[.!?]?\s*$/i.test(text);
        await askForPin(msg, user, bare && last && Date.now() - last.at < 10 * 60 * 1000 ? last.text : text);
        return;
      }
    }

    if (asksForFull(text)) {
      const bare = /^\s*(?:show\s+|give\s+me\s+)?(?:it\s+)?(?:full|unmask|reveal|complete)(?:\s+(?:it|details?|number|info))?\s*[.!?]?\s*$/i.test(text);
      const last = lastQuestion.get(id);
      const question = bare && last && Date.now() - last.at < 10 * 60 * 1000 ? last.text : text;
      if (!revealActive(id)) { await askForPin(msg, user, question); return; }
      await reply(msg, await withProgress(msg, () => answer(msg, user, question)));
      stats.answered += 1; stats.lastAnsweredAt = Date.now();
      return;
    }
    lastQuestion.set(id, { text, at: Date.now() });
    if (lastQuestion.size > 2000) lastQuestion.delete(lastQuestion.keys().next().value);

    if (!aiService.isConfigured() && !/^(hi|hello|hey|help|menu|start|documents?|my documents?|docs)$/i.test(text)) {
      await msg.reply('The AI service is not available right now. Please try again later.');
      return;
    }

    await reply(msg, await withProgress(msg, () => answer(msg, user, text)));
    stats.answered += 1; stats.lastAnsweredAt = Date.now();
    console.log(`[whatsapp] answered a linked member (${text.length} characters in)`);
  } catch (error) {
    if (error.name === 'AIPolicyViolationError') {
      await msg.reply('I cannot do that for an account with device-side encryption. Please use the FormOS app.');
      return;
    }
    stats.failed += 1; stats.lastError = `${error?.name || 'Error'}: ${String(error?.message ?? error)}`.slice(0, 200);
    const where = String(error?.stack || '').split('\n').slice(1, 3).map((l) => l.trim().replace(/\(.*[\\/]/, '(')).join(' | ');
    console.error(`[whatsapp] could not handle a message: ${error?.name || 'Error'}: ${String(error?.message ?? error)}${where ? ` [${where}]` : ''}`);
    await msg.reply('Sorry, something went wrong on my side. Please try again in a moment.').catch(() => {});
  }
}

exports.handleIncoming = handleIncoming;
exports.askKind = askKind;
exports.handleKindReply = handleKindReply;
exports.attach = (wa) => wa.onMessage(handleIncoming);
exports.HELP = HELP;
// Closes a member's opened vault now, for example when they switch the setting off.
exports.closeVaultFor = (userId) => { closeVault(userId); revealUntil.delete(String(userId)); awaitingPin.delete(String(userId)); };
// For tests only: forgets the per-sender rate limits.
exports._resetLimits = () => { hits.clear(); };
