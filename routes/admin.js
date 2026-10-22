const express = require('express');
const { body } = require('express-validator');
const authMiddleware = require('../middleware/auth');
const requireStepUp = require('../middleware/requireStepUp');
const { requireAdmin, requireSuperadmin } = require('../middleware/requireAdmin');
const { adminLimiter, adminLoginLimiter } = require('../middleware/authRateLimits');
const admin = require('../controllers/adminController');

const router = express.Router();

// The one route open to the public: step one of the console sign-in. Everything below it needs a session.
router.post(
  '/auth/login',
  adminLoginLimiter,
  [body('email').isString().isLength({ min: 3, max: 254 }), body('password').isString().isLength({ min: 1, max: 128 })],
  admin.login
);

// Tells the console whether the authenticator code is asked for (public: it reveals only a setting)
router.get('/auth/config', admin.getConfig);

// Every admin route needs a valid session AND an admin role loaded from the database.
router.use(authMiddleware, requireAdmin, adminLimiter);

// Read-only
router.get('/stats', admin.getStats);
router.get('/users', admin.listUsers);
router.get('/users/:id', admin.getUser);
router.get('/audit', admin.listAudit);
router.get('/pending-registrations', admin.listPendingRegistrations);
router.get('/whatsapp', admin.getWhatsApp);

// Every change needs a fresh re-authentication (PIN / authenticator) and is audit-logged.
router.post('/users/:id/suspend', requireStepUp, admin.suspendUser);
router.post('/users/:id/unsuspend', requireStepUp, admin.unsuspendUser);
router.post('/users/:id/revoke-sessions', requireStepUp, admin.revokeUserSessions);
router.delete('/users/:id/sessions/:sessionId', requireStepUp, admin.revokeUserSession);
router.post('/users/:id/reset-mfa', requireStepUp, admin.resetUserMfa);
router.delete('/users/:id/reset-mfa', requireStepUp, admin.cancelUserMfaReset);
router.post('/users/:id/send-pin-reset', requireStepUp, admin.sendPinReset);
router.delete('/users/:id/documents/:docId', requireStepUp, admin.deleteUserDocument);
router.delete('/pending-registrations/:id', requireStepUp, admin.deletePendingRegistration);

router.post('/whatsapp/connect', requireStepUp, admin.connectWhatsApp);
router.post('/whatsapp/restart', requireStepUp, admin.restartWhatsApp);
router.post('/whatsapp/disconnect', requireStepUp, admin.disconnectWhatsApp);

// Super administrator only
router.put('/users/:id/role', requireSuperadmin, requireStepUp, admin.changeRole);
router.delete('/users/:id', requireSuperadmin, requireStepUp, admin.deleteUser);

module.exports = router;
