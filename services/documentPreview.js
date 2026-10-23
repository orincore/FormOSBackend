// What the app shows to help a member recognise a document at a glance: its kind, its title, a one-line summary, the last four
// digits of its ID number, and a few key facts. Built only from the saved record, so it works for any kind of document the AI
// has read, and never carries a full ID number or any other sensitive value.

const sharp = require('sharp');
const docFields = require('./documentFields');
const docKind = require('./whatsappDocKind');
const { maskSensitiveText } = require('./securityService');

const KIND_LABEL = {
  aadhaar: 'Aadhaar card', pan: 'PAN card', passport: 'Passport', license: 'Driving licence', voter: 'Voter ID',
  marksheet: 'Marksheet', resume: 'Resume', certificate: 'Certificate', bank: 'Bank document', vehicle: 'Vehicle registration', insurance: 'Insurance',
};
// The number printed on each kind of ID, whose last four digits are shown on its card.
const ID_FIELD = { aadhaar: 'aadhaarNumber', pan: 'panNumber', passport: 'passportNumber', license: 'drivingLicenseNumber' };
const TOP_LEVEL = new Set(['aadhaar', 'pan', 'passport', 'license']);

// Facts worth showing on a card, best first. Anything long, or that looks like a personal number, is left out.
const FACT_PRIORITY = [/total.?experience|experience/i, /^skills?$|skill/i, /score/i, /percentage|percent|cgpa|gpa|grade|class awarded/i, /^result$|status/i, /total|aggregate|balance|outstanding|amount|limit/i, /valid|expiry|expires|due/i, /date|issued|year|exam/i, /seat|roll|enrol|policy|account|number|no$/i];
const SKIP_FACT = /control|enrol|aadhaar|pan\b|passport|licen[cs]e|account\s*number|phone|mobile|email|address|pincode|zip/i;

const last4 = (value) => {
  const compact = String(value || '').replace(/[^A-Za-z0-9]/g, '');
  return compact.length >= 4 ? compact.slice(-4).toUpperCase() : '';
};

// The kind of document: what the AI decided and saved, else the kind kept on the document, else a guess from its text
// (older documents that were saved before the AI read them).
function kindOf(document) {
  const sd = document.structuredData || {};
  if (TOP_LEVEL.has(document.documentType)) return document.documentType;
  if (TOP_LEVEL.has(sd.documentType)) return sd.documentType;
  if (sd.documentType && sd.documentType !== 'other') return sd.documentType;
  if (document.extractedText && !sd.documentTitle) {
    const guess = docKind.kindFromOcrText(document.extractedText);
    if (guess && KIND_LABEL[guess.key]) return guess.key;
  }
  return 'other';
}

// `reveal` is true only after the member confirmed their PIN: otherwise every ID number is masked, including inside the AI's sentence.
function buildPreview(document, { reveal = false } = {}) {
  const safe = (text) => (reveal ? String(text || '') : maskSensitiveText(String(text || '')));
  const sd = docFields.cleanKnown(document.structuredData || {});
  const kind = kindOf(document);
  const title = safe(String(sd.documentTitle || '').trim()) || KIND_LABEL[kind] || 'Document';
  const idField = ID_FIELD[kind];

  const facts = [];
  const extras = Object.entries(sd).filter(([k, v]) => !docFields.KNOWN_KEYS.includes(k) && !docFields.HIDDEN_KEYS.has(k) && !docFields.ALIAS_KEYS.has(k) && k !== 'city' && k !== 'district' && typeof v === 'string' && v.length <= 40 && !/;/.test(v) && !SKIP_FACT.test(`${k} ${docFields.labelOf(k)}`));
  for (const re of FACT_PRIORITY) {
    for (const [k, v] of extras) {
      if (facts.length >= 3) break;
      if (re.test(k) && !facts.some((f) => f.key === k)) facts.push({ key: k, label: docFields.labelOf(k), value: safe(v) });
    }
  }
  return {
    kind,
    kindLabel: KIND_LABEL[kind] || 'Document',
    title,
    summary: safe(String(sd.documentSummary || '').trim()),
    last4: idField && sd[idField] ? last4(sd[idField]) : '',
    holder: sd.fullName || '',
    facts: facts.map(({ label, value }) => ({ label, value })),
  };
}

// A small picture of a photo or scan, kept with the document so lists can show it without loading the file.
async function makeThumbnail(buffer, mimeType) {
  if (!/^image\/(jpeg|png|webp)$/.test(mimeType || '')) return '';
  try {
    const jpeg = await sharp(buffer, { failOn: 'none' }).rotate().resize({ width: 360, height: 260, fit: 'inside', withoutEnlargement: true }).jpeg({ quality: 62 }).toBuffer();
    return jpeg.length <= 60000 ? `data:image/jpeg;base64,${jpeg.toString('base64')}` : '';
  } catch {
    return '';
  }
}

module.exports = { buildPreview, makeThumbnail, kindOf, KIND_LABEL, ID_FIELD, TOP_LEVEL };
