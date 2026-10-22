#!/usr/bin/env node
// Copies existing uploaded files into Cloudflare R2 and points their records at the copy.
//   - plain files in AWS S3 (storageType "s3"): the same key is written to R2
//   - encrypted files in GridFS: stored in R2 under encrypted/<user>/..., record becomes storageType "r2"
// It never deletes anything: the originals stay where they are until you remove them yourself.
// Each copy is read back and compared before its record is changed, and files already copied are skipped.
//
//   node scripts/migrate-storage-to-r2.js            (dry run: only reports what it would do)
//   node scripts/migrate-storage-to-r2.js --apply
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const mongoose = require('mongoose');
const { S3Client, GetObjectCommand } = require('@aws-sdk/client-s3');
const { isR2Configured, putObject, downloadFromS3 } = require('../services/s3Service');
const Document = require('../models/Document');
const StorageService = require('../services/storageService');

const apply = process.argv.includes('--apply');

const streamToBuffer = async (stream) => { const c = []; for await (const x of stream) c.push(x); return Buffer.concat(c); };

(async () => {
  if (!isR2Configured()) { console.error('R2 is not configured in backend/.env.'); process.exit(1); }
  await mongoose.connect(process.env.MONGODB_URI || process.env.MONGO_URI);

  const aws = process.env.AWS_ACCESS_KEY_ID && process.env.AWS_S3_BUCKET
    ? new S3Client({ region: process.env.AWS_REGION || 'us-east-1', credentials: { accessKeyId: process.env.AWS_ACCESS_KEY_ID, secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY } })
    : null;

  const docs = await Document.find({ storageType: { $in: ['s3', 'gridfs'] } });
  console.log(`${apply ? 'APPLYING' : 'DRY RUN'}: ${docs.length} file(s) to look at\n`);
  let copied = 0, skipped = 0, failed = 0;

  for (const doc of docs) {
    const label = `${doc._id} (${doc.storageType}, ${doc.securityVersion === 2 ? 'encrypted' : 'plain'}, ${doc.fileSize || '?'} bytes)`;
    try {
      if (doc.storageType === 's3') {
        if (!doc.s3Key) { console.log(`skip  ${label}: no storage key`); skipped++; continue; }
        // Already in R2? Then there is nothing to do.
        try { await downloadFromS3(doc.s3Key); console.log(`ok    ${label}: already readable from R2`); skipped++; continue; } catch { /* not in R2 yet */ }
        if (!aws) { console.log(`FAIL  ${label}: AWS settings are missing, cannot read the original`); failed++; continue; }
        if (!apply) { console.log(`would copy ${label} key ${doc.s3Key}`); continue; }
        const original = await streamToBuffer((await aws.send(new GetObjectCommand({ Bucket: process.env.AWS_S3_BUCKET, Key: doc.s3Key }))).Body);
        await putObject(doc.s3Key, original, doc.mimeType);
        const back = await downloadFromS3(doc.s3Key);
        if (!back.equals(original)) throw new Error('the copy did not match the original');
        console.log(`copied ${label}`); copied++;
      } else {
        if (!doc.gridfsId) { console.log(`skip  ${label}: no GridFS id`); skipped++; continue; }
        if (!apply) { console.log(`would move ${label} to R2`); continue; }
        const original = await StorageService.downloadFile(doc);
        const stored = await StorageService.uploadEncrypted(original, doc.mimeType, doc.userId);
        const back = await StorageService.downloadFile({ securityVersion: 2, storageType: 'r2', s3Key: stored.s3Key });
        if (!back.equals(original)) throw new Error('the copy did not match the original');
        doc.storageType = 'r2'; doc.s3Key = stored.s3Key; doc.filePath = stored.s3Key;
        await doc.save();
        console.log(`moved ${label} -> ${stored.s3Key}`); copied++;
      }
    } catch (error) {
      console.log(`FAIL  ${label}: ${error.message}`); failed++;
    }
  }
  console.log(`\nDone. copied ${copied}, already fine/skipped ${skipped}, failed ${failed}.`);
  if (apply && copied) console.log('Originals were NOT deleted. Remove them from AWS S3 / GridFS yourself once you have checked the files open.');
  await mongoose.disconnect();
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
