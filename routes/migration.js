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

// Security V2 is retired: nothing new can be moved into it.
const retired = (req, res) => res.status(410).json({ success: false, code: 'V2_RETIRED', message: 'Security V2 has been retired. Documents are now read by the AI when they are uploaded.' });
router.post('/profile', authMiddleware, retired);
router.post('/upload-document/:id', authMiddleware, retired);
router.get('/download-temp-document/:tempGridfsId', authMiddleware, retired);
router.post('/commit-document/:id', authMiddleware, retired);
router.post('/complete', authMiddleware, retired);
router.post('/failed', authMiddleware, retired);

// Moving an existing Security V2 account to standard storage. Both steps that change anything need a recent re-authentication.
const downgrade = require('../controllers/downgradeController');
const requireStepUp = require('../middleware/requireStepUp');
router.get('/downgrade/status', authMiddleware, downgrade.status);
router.post('/downgrade/copy', authMiddleware, requireStepUp, upload.single('document'), downgrade.receiveCopy);
router.post('/downgrade/finish', authMiddleware, requireStepUp, downgrade.finish);

module.exports = router;
