const express = require('express');
const { body } = require('express-validator');
const authController = require('../controllers/authController');
const oauthController = require('../controllers/oauthController');
const authMiddleware = require('../middleware/auth');
const requireStepUp = require('../middleware/requireStepUp');
const {
  loginLimiter,
  loginMfaLimiter,
  signupEmailVerifyLimiter,
  signupMfaVerifyLimiter,
  signupStartLimiter,
} = require('../middleware/authRateLimits');

const router = express.Router();

const registrationDetailsValidation = [
  body('email').isEmail().normalizeEmail(),
  body('name').trim().isLength({ min: 2 }),
  body('pin').isLength({ min: 6, max: 6 }).isNumeric(),
  body('phone').optional({ checkFalsy: true }).isMobilePhone(),
];

const registrationIdValidation = [
  body('registrationId').isMongoId(),
];

const verifyEmailValidation = [
  body('registrationId').isMongoId(),
  body('emailCode').isLength({ min: 6, max: 6 }).isNumeric(),
];

const verifySignupMfaValidation = [
  body('registrationId').isMongoId(),
  body('totpCode').isLength({ min: 6, max: 8 }),
];

const completeSignupValidation = [
  body('registrationId').isMongoId(),
  body('recoveryCodesConfirmed').isBoolean(),
];

const loginValidation = [
  body('email').isEmail().normalizeEmail(),
  body('pin').isLength({ min: 6, max: 6 }).isNumeric(),
];

const loginMfaValidation = [
  body('challengeToken').isString().notEmpty(),
  body('totpCode').optional({ checkFalsy: true }).isLength({ min: 6, max: 8 }),
  body('recoveryCode').optional({ checkFalsy: true }).isString(),
];

router.post('/signup/start', signupStartLimiter, registrationDetailsValidation, authController.startSignup);
router.post('/signup/resend-email-code', signupStartLimiter, registrationIdValidation, authController.resendSignupEmailCode);
router.post('/signup/verify-email', signupEmailVerifyLimiter, verifyEmailValidation, authController.verifySignupEmail);
router.post('/signup/verify-mfa', signupMfaVerifyLimiter, verifySignupMfaValidation, authController.verifySignupMfa);
router.post('/signup/complete', signupMfaVerifyLimiter, completeSignupValidation, authController.completeSignup);

router.post('/login', loginLimiter, loginValidation, authController.login);
router.post('/login/verify-mfa', loginMfaLimiter, loginMfaValidation, authController.verifyLoginMfa);
router.post('/login/mfa/send-email-otp', loginMfaLimiter, [body('challengeToken').isString().notEmpty()], authController.sendMfaEmailOtp);
router.post('/login/otp/request', loginLimiter, [body('email').isEmail().normalizeEmail()], authController.requestLoginOtp);
router.post('/login/otp/verify', loginMfaLimiter, [body('email').isEmail().normalizeEmail(), body('code').isLength({ min: 6, max: 6 }).isNumeric()], authController.verifyLoginOtp);
router.get('/google', oauthController.startGoogle);
router.get('/google/callback', oauthController.googleCallback);
router.get('/github', oauthController.startGitHub);
router.get('/github/callback', oauthController.githubCallback);
router.post('/oauth/result/consume', [body('flow').isString().notEmpty()], oauthController.consumeResult);
router.post('/oauth/link/start', authMiddleware, requireStepUp, [body('provider').isIn(['google', 'github'])], oauthController.startLink);
router.delete('/providers/:provider', authMiddleware, requireStepUp, oauthController.unlinkProvider);

router.get('/me', authMiddleware, authController.getProfile);
router.get('/me/reveal', authMiddleware, requireStepUp, authController.getFullProfile);
router.put('/profile', authMiddleware, authController.updateProfile);

router.post('/step-up', authMiddleware, loginMfaLimiter, authController.stepUp);
router.post('/logout', authMiddleware, authController.logout);

router.get('/sessions', authMiddleware, authController.listSessions);
router.post('/logout-others', authMiddleware, requireStepUp, authController.logoutOtherSessions);
router.post('/logout-all', authMiddleware, requireStepUp, authController.logoutAllSessions);
router.delete('/sessions/:sessionId', authMiddleware, requireStepUp, authController.revokeSession);

router.put(
  '/email',
  authMiddleware,
  requireStepUp,
  [body('email').isEmail().normalizeEmail()],
  authController.updateEmail
);

router.put(
  '/pin',
  authMiddleware,
  requireStepUp,
  [
    body('currentPin').optional({ checkFalsy: true }).isLength({ min: 6, max: 6 }).isNumeric(),
    body('newPin').isLength({ min: 6, max: 6 }).isNumeric(),
  ],
  authController.updatePin
);

router.post('/mfa/recovery-codes/regenerate', authMiddleware, requireStepUp, authController.regenerateRecoveryCodes);

module.exports = router;
