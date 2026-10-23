// Re-reads a member's saved (standard account) documents with the current reader and cleans their stored fields.
//
//   node scripts/reread-documents.js <email> [--apply] [--no-ai]
//
// By default nothing is written: it prints, per document, which fields would be added, removed or changed (names only,
// never the values). With --apply the cleaned fields are saved. --no-ai skips the AI review and uses the local reader only.
// Only the document's own stored text is used (no photo is read again), and encrypted (Security V2) documents are skipped.
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '../.env') });
const mongoose = require('mongoose');
const User = require('../models/User');
const Document = require('../models/Document');
const ocrService = require('../services/ocrService');
const docFields = require('../services/documentFields');
const aiService = require('../services/aiService');
const { findUserByEmail } = require('../services/accountService');

const TYPE_LABEL = { aadhaar: 'Aadhaar card', pan: 'PAN card', passport: 'Passport', license: 'Driving licence', voter: 'Voter ID card' };

(async () => {
  const args = process.argv.slice(2);
  const email = args.find((a) => !a.startsWith('--'));
  const apply = args.includes('--apply');
  const useAi = !args.includes('--no-ai');
  if (!email) { console.error('Usage: node scripts/reread-documents.js <email> [--apply] [--no-ai]'); process.exit(1); }

  await mongoose.connect(process.env.MONGODB_URI);
  const user = await findUserByEmail(email);
  if (!user) { console.error(`No account found for ${email}.`); await mongoose.disconnect(); process.exit(1); }
  if (user.securityVersion === 2) { console.error('This account is encrypted (Security V2): its documents are not read on the server.'); await mongoose.disconnect(); process.exit(1); }

  const docs = await Document.find({ userId: user._id, securityVersion: { $ne: 2 }, ocrStatus: 'completed', extractedText: { $exists: true, $ne: '' } }).sort({ uploadedAt: -1 });
  console.log(`${docs.length} document(s) for ${email}${apply ? '' : ' (dry run, nothing is written)'}`);

  for (const doc of docs) {
    const old = doc.structuredData || {};
    const known = ocrService.parseStructuredData(doc.extractedText);
    const read = await docFields.extractFields({ text: doc.extractedText, known, aiService: useAi ? aiService : null, user, typeLabel: TYPE_LABEL[known.documentType] || '', fileName: doc.originalName });
    const fresh = docFields.assembleStructured({ known, fields: read.fields, documentTitle: read.documentTitle });
    // Repair, never rebuild: good fields are kept, junk is removed, typed values are tidied, missing fields are added.
    const { record, notes } = docFields.repairRecord(old, fresh);
    // a title the member confirmed or corrected in the chat is kept; otherwise a better one replaces a junk or placeholder title
    const oldTitle = typeof old.documentTitle === 'string' ? old.documentTitle : '';
    const titleIsJunk = !oldTitle || /[<>]/.test(oldTitle) || oldTitle !== fresh.documentTitle && /^(?:programme|course|diploma)\b/i.test(oldTitle);
    const title = doc.typeConfirmedAt && oldTitle ? oldTitle : (titleIsJunk && fresh.documentTitle ? fresh.documentTitle : oldTitle || fresh.documentTitle);
    let next = title ? { ...record, documentTitle: title } : record;
    if (useAi) next = (await docFields.reviewWithAI({ text: doc.extractedText, record: next, aiService, user })).record;

    const keys = new Set([...Object.keys(old), ...Object.keys(next)]);
    const added = [...keys].filter((k) => !(k in old) && k in next);
    const removed = [...keys].filter((k) => k in old && !(k in next));
    const changed = [...keys].filter((k) => k in old && k in next && String(old[k]) !== String(next[k]));
    console.log(`\n${String(doc._id).slice(-6)}  ${doc.originalName}`);
    console.log(`  added:   ${added.join(', ') || '-'}\n  removed: ${removed.join(', ') || '-'}\n  changed: ${changed.join(', ') || '-'}`);
    if (apply) {
      await Document.updateOne({ _id: doc._id }, { $set: { structuredData: next, fieldsExtractedAt: new Date() } });
      console.log('  saved');
    }
  }
  await mongoose.disconnect();
  process.exit(0);
})().catch((error) => { console.error(error.message); process.exit(1); });
