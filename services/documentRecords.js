// What FormOS saved from a member's documents, written out as plain records for the AI to answer from or to judge against.
// Standard accounts only. Aadhaar, PAN, passport and licence numbers are masked here, so no AI call can repeat a full ID number.

const Document = require('../models/Document');
const docFields = require('./documentFields');
const { FIELD_LABEL, SENSITIVE } = require('./fieldRules');

const KIND_LABEL = { aadhaar: 'Aadhaar card', pan: 'PAN card', passport: 'Passport', license: 'Driving licence', voter: 'Voter ID card', vehicle: 'Vehicle registration (RC)', marksheet: 'Marksheet', certificate: 'Certificate', bank: 'Bank document', insurance: 'Insurance', resume: 'Resume' };

const maskIds = (text) => String(text)
  .replace(/\b\d{4}\s?\d{4}\s?\d{4}\b/g, (m) => `****${m.replace(/\s/g, '').slice(-4)}`)
  .replace(/\b[A-Z]{5}\d{4}[A-Z]\b/g, (m) => `****${m.slice(-4)}`);

const last4 = (v) => `****${String(v).replace(/[^A-Za-z0-9]/g, '').slice(-4)}`;

/**
 * One text block per document (newest first), plus, first, a block for the account profile.
 * @param {object} user  a User document (needs _id, name, extractedData)
 * @param {{ profile?: boolean, limit?: number, maxChars?: number }} options
 */
async function recordsFor(user, { profile = true, limit = 25, maxChars = 40000 } = {}) {
  const rows = await Document.find({ userId: user._id, securityVersion: { $ne: 2 }, ocrStatus: 'completed' })
    .sort({ uploadedAt: -1 }).limit(limit).select('originalName uploadedAt structuredData').lean();
  const blocks = [];
  let total = 0;
  if (profile) {
    const saved = user.extractedData || {};
    const lines = Object.keys(FIELD_LABEL).filter((k) => saved[k]).map((k) => `${FIELD_LABEL[k]}: ${SENSITIVE.has(k) ? last4(saved[k]) : maskIds(String(saved[k]).slice(0, 300))}`);
    if (user.name || lines.length) blocks.push(['Account profile (the person asking)', user.name ? `Account name: ${user.name}` : '', ...lines].filter(Boolean).join('\n'));
  }
  rows.forEach((d, i) => {
    const sd = docFields.cleanKnown(d.structuredData || {});
    const lines = Object.entries(sd)
      .filter(([k, v]) => !docFields.HIDDEN_KEYS.has(k) && !docFields.ALIAS_KEYS.has(k) && v !== '' && v != null)
      .map(([k, v]) => `${docFields.labelOf(k)}: ${SENSITIVE.has(k) ? last4(v) : maskIds(String(v).slice(0, 600))}`);
    const head = `Document ${i + 1}: ${maskIds(sd.documentTitle || '') || KIND_LABEL[sd.documentType] || d.originalName} (file ${d.originalName}, added ${new Date(d.uploadedAt).toLocaleDateString('en-GB')})`;
    const block = [head, sd.documentSummary ? `Summary: ${maskIds(sd.documentSummary)}` : '', ...lines].filter(Boolean).join('\n');
    if (total + block.length > maxChars) return;
    total += block.length;
    blocks.push(block);
  });
  return blocks;
}

module.exports = { recordsFor, maskIds, KIND_LABEL };
