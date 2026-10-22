const express = require('express');
const authMiddleware = require('../middleware/auth');
const requireStepUp = require('../middleware/requireStepUp');
const { whatsappLinkLimiter, whatsappVerifyLimiter } = require('../middleware/authRateLimits');
const controller = require('../controllers/whatsappController');

const router = express.Router();
router.use(authMiddleware);

router.get('/status', controller.getStatus);
// Linking and unlinking hand over (or take back) access to the person's documents through a phone,
// so both need a fresh re-authentication, like other sensitive account changes.
router.post('/link', requireStepUp, whatsappLinkLimiter, controller.startLink);
router.post('/link/verify', whatsappVerifyLimiter, controller.verifyLink);
router.delete('/link/pending', controller.cancelPending);
router.delete('/link', requireStepUp, controller.unlink);
router.put('/encrypted-access', requireStepUp, controller.setEncryptedAccess);

module.exports = router;
