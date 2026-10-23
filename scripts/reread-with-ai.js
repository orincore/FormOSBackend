// One-time re-read of standard documents that were saved by the older reader, with the AI reader, so that every later question
// is answered from complete saved data. Safe by default: it only lists what it would do. Add --apply to do it.
//
//   node scripts/reread-with-ai.js                 # list
//   node scripts/reread-with-ai.js --apply         # re-read all
//   node scripts/reread-with-ai.js --apply --email someone@example.com
//
// Encrypted (Security V2) documents are never touched. A document whose re-read fails keeps its earlier data.
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const mongoose = require('mongoose');
const Document = require('../models/Document');
const User = require('../models/User');
const { reprocessDocument } = require('../controllers/documentController');

(async () => {
  const apply = process.argv.includes('--apply');
  const at = process.argv.indexOf('--email');
  // --resumes: read again the documents that were saved as a resume before resumes were captured in full
  const resumes = process.argv.includes('--resumes');
  const query = resumes ? { securityVersion: { $ne: 2 }, 'structuredData.documentTitle': /resume|curriculum vitae|\bcv\b/i, mimeType: { $in: ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'] } } : { securityVersion: { $ne: 2 }, aiReadAt: { $exists: false }, mimeType: { $in: ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'] } };
  await mongoose.connect(process.env.MONGODB_URI || process.env.MONGO_URI);
  if (at !== -1) {
    const user = await User.findOne({ email: String(process.argv[at + 1] || '').toLowerCase() }).select('_id');
    if (!user) { console.log('No account with that email.'); process.exit(1); }
    query.userId = user._id;
  }
  const docs = await Document.find(query).sort({ uploadedAt: 1 }).select('originalName mimeType fileSize uploadedAt storageType userId');
  console.log(`${docs.length} standard document(s) have not been read by the AI reader.`);
  if (!apply) {
    docs.slice(0, 50).forEach((d) => console.log(`  ${d.uploadedAt.toISOString().slice(0, 10)}  ${d.mimeType.padEnd(16)} ${String(Math.round(d.fileSize / 1024)).padStart(6)} KB  ${d.originalName}`));
    console.log('Nothing was changed. Run again with --apply to re-read them.');
    process.exit(0);
  }
  let done = 0; let failed = 0;
  for (const d of docs) {
    try {
      await reprocessDocument(d);
      const after = await Document.findById(d._id).select('aiReadAt ocrStatus');
      if (after.aiReadAt) { done += 1; console.log(`  read: ${d.originalName}`); } else { failed += 1; console.log(`  kept earlier data: ${d.originalName}`); }
    } catch (error) {
      failed += 1; console.log(`  failed: ${d.originalName} (${error.message})`);
    }
  }
  console.log(`Done. ${done} re-read, ${failed} kept their earlier data.`);
  process.exit(0);
})();
