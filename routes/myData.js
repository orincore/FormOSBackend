const express = require('express');
const router = express.Router();
const authMiddleware = require('../middleware/auth');
const requireStepUp = require('../middleware/requireStepUp');
const c = require('../controllers/myDataController');

// Reading is masked. Showing full values and every change need a recent PIN check.
router.get('/', authMiddleware, c.get(false));
router.get('/reveal', authMiddleware, requireStepUp, c.get(true));

router.put('/profile/:key', authMiddleware, requireStepUp, c.setProfile);
router.delete('/profile/:key', authMiddleware, requireStepUp, c.deleteProfile);
router.delete('/custom/:label', authMiddleware, requireStepUp, c.deleteCustom);
router.put('/documents/:id/fields/:key', authMiddleware, requireStepUp, c.setDocumentField);
router.delete('/documents/:id/fields/:key', authMiddleware, requireStepUp, c.deleteDocumentField);
router.delete('/documents/:id/data', authMiddleware, requireStepUp, c.clearDocument);
router.post('/forget', authMiddleware, requireStepUp, c.forget);

module.exports = router;
