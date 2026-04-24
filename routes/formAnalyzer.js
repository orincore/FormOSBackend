const express = require('express');
const router = express.Router();
const formAnalyzerController = require('../controllers/formAnalyzerController');
const auth = require('../middleware/auth');
const multer = require('multer');
const path = require('path');
const { isS3Configured, s3Storage } = require('../services/s3Service');

// Configure multer for file uploads
const localStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, process.env.UPLOAD_DIR || './uploads');
  },
  filename: (req, file, cb) => {
    cb(null, `form-${Date.now()}-${file.originalname}`);
  }
});

// Use S3 storage if configured, otherwise use local storage
const storage = isS3Configured() ? s3Storage : localStorage;

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|pdf/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (extname && mimetype) {
      cb(null, true);
    } else {
      cb(new Error('Only images (JPEG, PNG) and PDF files are allowed'));
    }
  }
});

console.log('Form Analyzer using storage:', isS3Configured() ? 'S3' : 'Local');

// Routes
router.post('/analyze', auth, upload.single('form'), formAnalyzerController.analyzeForm);
router.get('/user-data', auth, formAnalyzerController.getUserData);
router.post('/prepare-autofill', auth, formAnalyzerController.prepareAutofill);
router.post('/update-field', auth, formAnalyzerController.updateField);

module.exports = router;
