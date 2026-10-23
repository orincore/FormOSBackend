const express = require('express');
const router = express.Router();
const authMiddleware = require('../middleware/auth');
const autofillController = require('../controllers/autofillController');

const rateLimit = require('express-rate-limit');
// Each smart fill is one AI call, so a runaway page or script cannot run up the bill.
const smartLimiter = rateLimit({ windowMs: 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false, message: { success: false, message: 'Too many smart fills. Wait a minute and try again.' } });

router.get('/', authMiddleware, autofillController.getAutofillData);
router.post('/smart', authMiddleware, smartLimiter, autofillController.smartFill);

module.exports = router;
