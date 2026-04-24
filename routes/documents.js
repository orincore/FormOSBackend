const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const authMiddleware = require('../middleware/auth');
const requireStepUp = require('../middleware/requireStepUp');
const documentController = require('../controllers/documentController');
const { s3Storage, isS3Configured } = require('../services/s3Service');

// Configure multer for local file upload (fallback)
const localStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, process.env.UPLOAD_DIR || './uploads');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/jpg', 'application/pdf'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only JPEG, PNG, and PDF are allowed.'), false);
  }
};

// Use S3 storage if configured, otherwise use local storage
const storage = isS3Configured() ? s3Storage : localStorage;

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024 // 10MB
  }
});

// Log storage mode
console.log(`📁 Document storage: ${isS3Configured() ? 'AWS S3' : 'Local filesystem'}`);


// Routes
router.post('/upload', authMiddleware, upload.single('document'), documentController.uploadDocument);
router.get('/', authMiddleware, documentController.getDocuments);
router.get('/:id/reveal', authMiddleware, requireStepUp, documentController.revealDocument);
router.get('/:id/download', authMiddleware, requireStepUp, documentController.downloadDocument);
router.get('/:id', authMiddleware, documentController.getDocument);
router.put('/:id', authMiddleware, requireStepUp, documentController.updateStructuredData);
router.delete('/:id', authMiddleware, documentController.deleteDocument);

module.exports = router;
