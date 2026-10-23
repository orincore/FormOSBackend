const express = require('express');
const authMiddleware = require('../middleware/auth');
const requireStepUp = require('../middleware/requireStepUp');
const { whatsappLinkLimiter, whatsappVerifyLimiter, whatsappSendDocLimiter } = require('../middleware/authRateLimits');
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
// The PIN in the request is the confirmation, so this does not also need a step-up.
router.post('/send-document', whatsappSendDocLimiter, controller.sendDocument);
router.put('/encrypted-access', requireStepUp, controller.setEncryptedAccess);

module.exports = router;
