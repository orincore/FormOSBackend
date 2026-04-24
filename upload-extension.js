/**
 * Run once after deploy to push the extension zip to S3:
 *   node backend/upload-extension.js
 */
require('dotenv').config({ path: __dirname + '/.env' });
const { s3Client, isS3Configured } = require('./services/s3Service');
const { PutObjectCommand } = require('@aws-sdk/client-s3');
const fs = require('fs').promises;
const path = require('path');

const EXTENSION_S3_KEY = 'downloads/chrome-extension.zip';

(async () => {
  if (!isS3Configured()) {
    console.error('❌ S3 not configured. Set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_S3_BUCKET in .env');
    process.exit(1);
  }

  const zipPath = path.join(__dirname, '../chrome-extension.zip');
  console.log('📦 Reading zip from:', zipPath);

  const buffer = await fs.readFile(zipPath);
  console.log(`📤 Uploading ${(buffer.length / 1024).toFixed(1)} KB to S3 as "${EXTENSION_S3_KEY}"...`);

  const command = new PutObjectCommand({
    Bucket: process.env.AWS_S3_BUCKET,
    Key: EXTENSION_S3_KEY,
    Body: buffer,
    ContentType: 'application/zip',
    ContentDisposition: 'attachment; filename="formos-chrome-extension.zip"',
  });

  await s3Client.send(command);
  console.log('✅ Uploaded successfully!');
  console.log(`   Key: ${EXTENSION_S3_KEY}`);
  console.log(`   Bucket: ${process.env.AWS_S3_BUCKET}`);
  console.log('\nNow call POST /api/extension/upload from the server to verify, or use the signed URL endpoint.');
})();
