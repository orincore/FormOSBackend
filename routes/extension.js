const express = require('express');
const router = express.Router();
const { s3Client, isS3Configured, getS3SignedUrl } = require('../services/s3Service');
const { PutObjectCommand } = require('@aws-sdk/client-s3');
const fs = require('fs').promises;
const path = require('path');

const EXTENSION_S3_KEY = 'downloads/chrome-extension.zip';
const LOCAL_ZIP_PATH = path.join(__dirname, '../../chrome-extension.zip');

// Upload zip directly to S3 with a fixed key (no documents/ prefix)
async function uploadExtensionToS3(buffer) {
  const command = new PutObjectCommand({
    Bucket: process.env.AWS_S3_BUCKET,
    Key: EXTENSION_S3_KEY,
    Body: buffer,
    ContentType: 'application/zip',
    ContentDisposition: 'attachment; filename="formos-chrome-extension.zip"',
  });
  await s3Client.send(command);
  return EXTENSION_S3_KEY;
}

// POST /api/extension/upload — upload zip to S3 (run once on deploy)
router.post('/upload', async (req, res) => {
  try {
    if (!isS3Configured()) {
      return res.status(503).json({ success: false, message: 'S3 not configured' });
    }
    const buffer = await fs.readFile(LOCAL_ZIP_PATH);
    const key = await uploadExtensionToS3(buffer);
    res.json({ success: true, message: 'Extension uploaded to S3', key });
  } catch (error) {
    console.error('Extension upload error:', error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// GET /api/extension/download-url — get a signed S3 URL (1 hour)
router.get('/download-url', async (req, res) => {
  try {
    if (!isS3Configured()) {
      return res.json({ success: true, url: null, fallback: true });
    }
    const url = await getS3SignedUrl(EXTENSION_S3_KEY, 3600);
    res.json({ success: true, url });
  } catch (error) {
    console.error('Extension download URL error:', error);
    res.status(500).json({ success: false, message: error.message });
  }
});

module.exports = router;
