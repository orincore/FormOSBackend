const express = require('express');
const router = express.Router();
const multer = require('multer');
const authMiddleware = require('../middleware/auth');
const migrationController = require('../controllers/migrationController');

// Multer memory storage configuration for secure buffers
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024 // 10MB
  }
});

router.post('/profile', authMiddleware, migrationController.migrateProfile);
router.post('/upload-document/:id', authMiddleware, upload.single('document'), migrationController.uploadDocumentMigration);
router.get('/download-temp-document/:tempGridfsId', authMiddleware, migrationController.downloadTempDocument);
router.post('/commit-document/:id', authMiddleware, migrationController.commitDocumentMigration);
router.post('/complete', authMiddleware, migrationController.completeMigration);
router.post('/failed', authMiddleware, migrationController.failMigration);

module.exports = router;
