const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const authMiddleware = require('../middleware/auth');
const requireStepUp = require('../middleware/requireStepUp');
const documentController = require('../controllers/documentController');

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/jpg', 'application/pdf', 'application/octet-stream'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only JPEG, PNG, PDF, and encrypted octet-streams are allowed.'), false);
  }
};

// Use memory storage to temporarily hold buffers and prevent S3/local leak before storage routing
const storage = multer.memoryStorage();

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024 // 10MB
  }
});

// Log storage mode
console.log('📁 Document storage: Managed by StorageService (Memory buffer)');

// Routes
router.post('/upload', authMiddleware, upload.single('document'), documentController.uploadDocument);
router.post('/secure-v2/upload', authMiddleware, upload.single('document'), documentController.uploadSecureV2Document);
router.get('/', authMiddleware, documentController.getDocuments);
router.get('/:id/reveal', authMiddleware, requireStepUp, documentController.revealDocument);
router.get('/:id/download', authMiddleware, requireStepUp, documentController.downloadDocument);
router.get('/:id', authMiddleware, documentController.getDocument);
router.get('/:id/secure-v2', authMiddleware, documentController.getSecureV2Document);
router.put('/:id/secure-v2', authMiddleware, documentController.updateSecureV2Document);
router.put('/:id', authMiddleware, requireStepUp, documentController.updateStructuredData);
router.delete('/:id', authMiddleware, documentController.deleteDocument);

module.exports = router;
