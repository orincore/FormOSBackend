#!/usr/bin/env node
// Checks the object storage settings in backend/.env: reaches the bucket, then writes, reads back and
// deletes a small test file. Prints which step failed, never the credentials.
//
//   node scripts/check-storage.js
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const { checkStorage, storageProvider } = require('../services/s3Service');

(async () => {
  const provider = storageProvider();
  console.log(`Storage provider: ${provider === 'r2' ? 'Cloudflare R2' : provider === 'aws' ? 'AWS S3' : 'none (files stay on this server)'}`);
  const result = await checkStorage();
  if (result.ok) {
    console.log(`OK: wrote, read back and deleted a test file in bucket "${result.bucket}".`);
    process.exit(0);
  }
  console.error(`FAILED while ${result.step}: ${result.message}`);
  if (provider === 'r2') {
    console.error('Check: R2_ACCOUNT_ID, R2_BUCKET (exact name), and that the API token has Object Read & Write on that bucket.');
  }
  process.exit(1);
})();
