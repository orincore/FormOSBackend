// Everything FormOS has saved about a member, and the ways they can change or remove it. Used by the "My data" page and by the
// WhatsApp assistant, so both follow the same rules.
//
// A detail (a phone number, a PAN ...) can live in two places: the member's profile, and the documents it was read from. A change or
// a removal is made in both, so the profile, the documents and every later answer agree.

const User = require('../models/User');
const Document = require('../models/Document');
const StorageService = require('./storageService');
const docFields = require('./documentFields');
const { FIELD_LABEL, SENSITIVE, cleanField } = require('./fieldRules');
const { maskStructuredData, maskSensitiveText } = require('./securityService');
const { buildPreview } = require('./documentPreview');

const ACCOUNT_KEYS = new Set(['email']); // the sign-in email is an account matter (verified separately), not a saved detail

// A stored value's text, with a value taken out or swapped, in the spaced and the unspaced spelling.
const swapIn = (text, stale, fresh) => {
  if (!text || !stale) return text;
  const squash = (v) => String(v).replace(/\s+/g, '');
  return String(text).split(String(stale)).join(fresh).split(squash(stale)).join(squash(fresh));
};

// The sentence and the text kept with an AI-read document are made from its fields, so they follow when a field changes.
function scrub(doc, stale, fresh = '') {
  const sd = { ...(doc.structuredData || {}) };
  if (sd.documentSummary) sd.documentSummary = swapIn(sd.documentSummary, stale, fresh);
  doc.structuredData = sd;
  doc.extractedText = swapIn(doc.extractedText, stale, fresh);
  doc.markModified('structuredData');
}

const isHidden = (key) => docFields.HIDDEN_KEYS.has(key) || docFields.ALIAS_KEYS.has(key);

// ---- reading -----------------------------------------------------------------------------------------------------
async function collect(userId, { reveal = false } = {}) {
  const user = await User.findById(userId).lean();
  if (!user) return null;
  const saved = user.extractedData || {};
  const show = (key, value) => {
    if (reveal) return value;
    const masked = maskStructuredData({ [key]: value });
    return typeof masked[key] === 'string' ? masked[key] : value;
  };

  const profile = Object.keys(FIELD_LABEL).map((key) => {
    const value = saved[key] || (key === 'fullName' ? user.name : key === 'email' ? user.email : key === 'phone' ? user.phone : '');
    return value ? { key, label: FIELD_LABEL[key], value: show(key, String(value)), sensitive: SENSITIVE.has(key) || ['dateOfBirth', 'phone', 'email', 'address'].includes(key), canEdit: !ACCOUNT_KEYS.has(key), canDelete: !ACCOUNT_KEYS.has(key) } : null;
  }).filter(Boolean);
  const custom = Object.entries(saved.customFields || {}).filter(([, v]) => v).map(([label, value]) => ({ label, value: String(value) }));

  const rows = await Document.find({ userId, securityVersion: { $ne: 2 } }).sort({ uploadedAt: -1 });
  const documents = rows.map((d) => {
    const sd = docFields.cleanKnown(d.structuredData || {});
    const preview = buildPreview(d, { reveal });
    const fields = Object.entries(sd)
      .filter(([k, v]) => !isHidden(k) && k !== 'city' && k !== 'district' && v !== '' && v != null)
      .map(([key, value]) => {
        const text = String(value);
        // Masked unless the member has confirmed their PIN: the usual sensitive fields by name, and any other value that looks like an ID.
        const named = maskStructuredData({ [key]: text })[key];
        const shown = reveal ? text : (named !== text ? named : (docFields.KNOWN_KEYS.includes(key) ? text : maskSensitiveText(text)));
        return { key, label: docFields.labelOf(key), value: shown, sensitive: SENSITIVE.has(key) || docFields.isSensitive(key, docFields.labelOf(key), text), known: docFields.KNOWN_KEYS.includes(key) };
      });
    return { id: String(d._id), title: preview.title, kind: preview.kind, kindLabel: preview.kindLabel, summary: preview.summary, file: d.originalName, size: d.fileSize, mime: d.mimeType, addedAt: d.uploadedAt, thumbnail: d.thumbnail || '', fields };
  });
  const encrypted = await Document.countDocuments({ userId, securityVersion: 2 });

  return {
    account: { name: user.name || '', email: user.email || '', createdAt: user.createdAt },
    profile, custom, documents, encryptedDocuments: encrypted,
    whatsapp: { linked: Boolean(user.whatsapp?.number), number: user.whatsapp?.number ? `******${String(user.whatsapp.number).slice(-4)}` : '' },
  };
}

// ---- changing ----------------------------------------------------------------------------------------------------
// A detail in the profile, and the same detail in the documents that hold it.
async function syncDetail(userId, key, fresh) {
  const set = { [`extractedData.${key}`]: fresh };
  if (key === 'phone') set.phone = fresh;
  if (key === 'fullName') set.name = fresh;
  await User.updateOne({ _id: userId }, { $set: set });
  const docs = await Document.find({ userId, securityVersion: { $ne: 2 }, [`structuredData.${key}`]: { $exists: true, $ne: '' } });
  for (const d of docs) {
    const stale = String(d.structuredData[key]);
    scrub(d, stale, fresh);
    d.structuredData = { ...d.structuredData, [key]: fresh };
    d.markModified('structuredData');
    await d.save();
  }
  return docs.length;
}

async function setProfileField(userId, key, raw) {
  if (!FIELD_LABEL[key] || ACCOUNT_KEYS.has(key)) return { error: 'That detail cannot be changed here.' };
  const checked = cleanField(key, raw);
  if (checked.error) return { error: `${FIELD_LABEL[key]}: ${checked.error}.` };
  const documents = await syncDetail(userId, key, checked.value);
  return { ok: true, value: checked.value, documents };
}

async function setDocumentField(userId, docId, key, raw) {
  const doc = await Document.findOne({ _id: docId, userId, securityVersion: { $ne: 2 } });
  if (!doc) return { error: 'Document not found.' };
  const current = (doc.structuredData || {})[key];
  if (current === undefined || isHidden(key)) return { error: 'That field is not on this document.' };
  let value = String(raw ?? '').trim();
  if (FIELD_LABEL[key]) {
    const checked = cleanField(key, value);
    if (checked.error) return { error: `${FIELD_LABEL[key]}: ${checked.error}.` };
    value = checked.value;
  } else if (!value || value.length > 500) {
    return { error: 'Enter between 1 and 500 characters.' };
  }
  scrub(doc, current, value);
  doc.structuredData = { ...doc.structuredData, [key]: value };
  doc.markModified('structuredData');
  await doc.save();
  if (FIELD_LABEL[key] && !ACCOUNT_KEYS.has(key)) await User.updateOne({ _id: userId }, { $set: { [`extractedData.${key}`]: value } });
  return { ok: true, value };
}

// ---- removing ----------------------------------------------------------------------------------------------------
// A detail from the profile, and (by default) from every document that holds it. The documents themselves stay.
async function deleteProfileField(userId, key, { everywhere = true } = {}) {
  if (!FIELD_LABEL[key] || ACCOUNT_KEYS.has(key)) return { error: 'That detail cannot be removed here.' };
  await User.updateOne({ _id: userId }, { $unset: { [`extractedData.${key}`]: 1 } });
  let documents = 0;
  if (everywhere) {
    const docs = await Document.find({ userId, securityVersion: { $ne: 2 }, [`structuredData.${key}`]: { $exists: true } });
    for (const d of docs) {
      const stale = String(d.structuredData[key] || '');
      const sd = { ...d.structuredData }; delete sd[key];
      d.structuredData = sd;
      scrub(d, stale, '');
      await d.save();
      documents += 1;
    }
  }
  return { ok: true, documents };
}

async function deleteDocumentField(userId, docId, key) {
  const doc = await Document.findOne({ _id: docId, userId, securityVersion: { $ne: 2 } });
  if (!doc || (doc.structuredData || {})[key] === undefined || isHidden(key)) return { error: 'That field is not on this document.' };
  const stale = String(doc.structuredData[key] || '');
  const sd = { ...doc.structuredData }; delete sd[key];
  doc.structuredData = sd;
  scrub(doc, stale, '');
  await doc.save();
  return { ok: true };
}

async function deleteCustomField(userId, label) {
  await User.updateOne({ _id: userId }, { $unset: { [`extractedData.customFields.${String(label).replace(/\./g, ' ')}`]: 1 } });
  return { ok: true };
}

// Everything FormOS read from one document, keeping the file itself.
async function clearDocumentData(userId, docId) {
  const doc = await Document.findOne({ _id: docId, userId, securityVersion: { $ne: 2 } });
  if (!doc) return { error: 'Document not found.' };
  const sd = doc.structuredData || {};
  doc.structuredData = { ...(sd.documentTitle ? { documentTitle: sd.documentTitle } : {}) };
  doc.extractedText = '';
  doc.markModified('structuredData');
  await doc.save();
  return { ok: true };
}

async function removeFile(doc) {
  await StorageService.deleteFile(doc).catch((error) => console.error('Delete file (non-fatal):', error.message));
}

// "Forget my details" removes the saved details (the profile and what was read from documents, keeping the files). "Everything"
// also deletes every document and its file. The sign-in account itself is never touched here.
async function forget(userId, { documents = false } = {}) {
  await User.updateOne({ _id: userId }, { $unset: { 'extractedData': 1 } });
  const docs = await Document.find({ userId, securityVersion: { $ne: 2 } });
  let deleted = 0;
  for (const d of docs) {
    if (documents) { await removeFile(d); await d.deleteOne(); deleted += 1; } else {
      d.structuredData = d.structuredData?.documentTitle ? { documentTitle: d.structuredData.documentTitle } : {};
      d.extractedText = ''; d.markModified('structuredData'); await d.save();
    }
  }
  return { ok: true, documents: docs.length, deleted };
}

// How many documents hold a detail (for the sentence that asks for confirmation).
const countHolding = (userId, key) => Document.countDocuments({ userId, securityVersion: { $ne: 2 }, [`structuredData.${key}`]: { $exists: true } });

module.exports = { collect, setProfileField, setDocumentField, deleteProfileField, deleteDocumentField, deleteCustomField, clearDocumentData, forget, syncDetail, countHolding, scrub };
