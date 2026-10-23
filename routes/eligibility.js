const express = require('express');
const router = express.Router();
const eligibilityController = require('../controllers/eligibilityController');
const authMiddleware = require('../middleware/auth');

router.post('/check', authMiddleware, eligibilityController.checkEligibility);
router.get('/context', authMiddleware, eligibilityController.context);

module.exports = router;
