const express = require('express');
const router = express.Router();
const { isS3Configured, putObject, getS3SignedUrl } = require('../services/s3Service');
const fs = require('fs').promises;
const path = require('path');

const EXTENSION_S3_KEY = 'downloads/chrome-extension.zip';
const LOCAL_ZIP_PATH = path.join(__dirname, '../../chrome-extension.zip');

// Only from a shell on the server itself (no proxy header, loopback address): publishing a new extension build is a deploy step.
const fromThisServer = (req) => !req.headers['x-forwarded-for'] && ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket.remoteAddress);

// POST /api/extension/upload: publish the zip that sits next to the backend folder to storage (R2 or S3, whichever is configured)
router.post('/upload', async (req, res) => {
  try {
    if (!fromThisServer(req)) return res.status(403).json({ success: false, message: 'Run this from the server.' });
    if (!isS3Configured()) {
      return res.status(503).json({ success: false, message: 'Object storage is not configured' });
    }
    const buffer = await fs.readFile(LOCAL_ZIP_PATH);
    const stored = await putObject(EXTENSION_S3_KEY, buffer, 'application/zip');
    res.json({ success: true, message: 'Extension published', key: stored.key, bytes: buffer.length });
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
