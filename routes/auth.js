const express = require('express');
const { body } = require('express-validator');
const authController = require('../controllers/authController');
const oauthController = require('../controllers/oauthController');
const authMiddleware = require('../middleware/auth');
const requireStepUp = require('../middleware/requireStepUp');
const {
  checkEmailLimiter,
  loginLimiter,
  loginMfaLimiter,
  otpRequestLimiter,
  passwordResetLimiter,
  signupEmailVerifyLimiter,
  signupMfaVerifyLimiter,
  signupResendLimiter,
  signupStartLimiter,
  stepUpLimiter,
} = require('../middleware/authRateLimits');

const router = express.Router();

// Trim + lowercase only. normalizeEmail() would rewrite Gmail addresses (strip dots and
// +tags), turning the address the user typed into a different one.
const emailField = (field = 'email') => body(field)
  .customSanitizer((value) => (typeof value === 'string' ? value.trim().toLowerCase() : value))
  .isEmail()
  .withMessage('Enter a valid email address');

const digitsOnly = (value) => (typeof value === 'string' ? value.replace(/\D/g, '') : value);

// 6-digit authenticator code; spaces/dashes pasted from an app are tolerated.
const totpCodeField = (field = 'totpCode') => body(field)
  .customSanitizer(digitsOnly)
  .matches(/^\d{6}$/)
  .withMessage('Enter the 6-digit code from your authenticator app');

const pinField = (field = 'pin') => body(field)
  .isString()
  .matches(/^\d{6}$/)
  .withMessage('PIN must be exactly 6 digits');

const registrationDetailsValidation = [
  emailField('email'),
  body('name').trim().isLength({ min: 2 }).withMessage('Enter your full name'),
  pinField('pin'),
  body('phone')
    .optional({ checkFalsy: true })
    .customSanitizer((value) => (typeof value === 'string' ? value.replace(/[\s\-().]/g, '') : value))
    .isMobilePhone('any')
    .withMessage('Enter a valid phone number, including country code'),
];

const registrationIdValidation = [
  body('registrationId').isMongoId().withMessage('Registration not found. Please start again.'),
];

const verifyEmailValidation = [
  body('registrationId').isMongoId().withMessage('Registration not found. Please start again.'),
  body('emailCode')
    .customSanitizer(digitsOnly)
    .matches(/^\d{6}$/)
    .withMessage('Enter the 6-digit code from your email'),
];

const verifySignupMfaValidation = [
  body('registrationId').isMongoId().withMessage('Registration not found. Please start again.'),
  totpCodeField('totpCode'),
];

const completeSignupValidation = [
  body('registrationId').isMongoId().withMessage('Registration not found. Please start again.'),
  body('recoveryCodesConfirmed').isBoolean(),
];

const loginValidation = [
  emailField('email'),
  pinField('pin'),
];

const loginMfaValidation = [
  body('challengeToken').isString().notEmpty(),
  body('totpCode').optional({ checkFalsy: true }).customSanitizer(digitsOnly).matches(/^\d{6}$/)
    .withMessage('Enter the 6-digit code from your authenticator app'),
  body('recoveryCode').optional({ checkFalsy: true }).isString().trim(),
  body('emailOtpCode').optional({ checkFalsy: true }).customSanitizer(digitsOnly).matches(/^\d{6}$/)
    .withMessage('Enter the 6-digit code from your email'),
];

router.post('/signup/start', signupStartLimiter, registrationDetailsValidation, authController.startSignup);
router.post('/signup/resend-email-code', signupResendLimiter, registrationIdValidation, authController.resendSignupEmailCode);
router.post('/signup/verify-email', signupEmailVerifyLimiter, verifyEmailValidation, authController.verifySignupEmail);
router.post('/signup/verify-mfa', signupMfaVerifyLimiter, verifySignupMfaValidation, authController.verifySignupMfa);
router.post('/signup/complete', signupMfaVerifyLimiter, completeSignupValidation, authController.completeSignup);

router.post('/login', loginLimiter, loginValidation, authController.login);
router.post('/login/verify-mfa', loginMfaLimiter, loginMfaValidation, authController.verifyLoginMfa);
router.post('/login/mfa/send-email-otp', otpRequestLimiter, [body('challengeToken').isString().notEmpty()], authController.sendMfaEmailOtp);
router.post('/login/otp/request', otpRequestLimiter, [emailField('email')], authController.requestLoginOtp);
router.post('/login/otp/verify', loginMfaLimiter, [emailField('email'), body('code').isLength({ min: 6, max: 6 }).isNumeric()], authController.verifyLoginOtp);

// Forgot Password Routes
router.post('/check-email', checkEmailLimiter, [emailField('email')], authController.checkEmail);
router.post('/forgot-password', otpRequestLimiter, [emailField('email')], authController.forgotPassword);
router.post('/verify-reset-code', passwordResetLimiter, [emailField('email'), body('code').isLength({ min: 6, max: 6 }).isNumeric()], authController.verifyResetCode);
router.post('/reset-password', passwordResetLimiter, [emailField('email'), body('code').isLength({ min: 6, max: 6 }).isNumeric(), pinField('newPin')], authController.resetPassword);

router.get('/google', oauthController.startGoogle);
router.get('/google/callback', oauthController.googleCallback);
router.get('/github', oauthController.startGitHub);
router.get('/github/callback', oauthController.githubCallback);
router.post('/oauth/result/consume', [body('flow').isString().notEmpty()], oauthController.consumeResult);
router.post('/oauth/link/start', authMiddleware, requireStepUp, [body('provider').isIn(['google', 'github'])], oauthController.startLink);
router.delete('/providers/:provider', authMiddleware, requireStepUp, oauthController.unlinkProvider);

router.get('/keys', authMiddleware, authController.getKeys);
router.get('/me', authMiddleware, authController.getProfile);
router.get('/me/reveal', authMiddleware, requireStepUp, authController.getFullProfile);
router.put('/profile', authMiddleware, authController.updateProfile);

router.post('/step-up', authMiddleware, stepUpLimiter, authController.stepUp);
router.post('/logout', authMiddleware, authController.logout);

router.get('/sessions', authMiddleware, authController.listSessions);
router.post('/logout-others', authMiddleware, requireStepUp, authController.logoutOtherSessions);
router.post('/logout-all', authMiddleware, requireStepUp, authController.logoutAllSessions);
router.delete('/sessions/:sessionId', authMiddleware, requireStepUp, authController.revokeSession);

router.put(
  '/email',
  authMiddleware,
  requireStepUp,
  [emailField('email')],
  authController.updateEmail
);

router.put(
  '/pin',
  authMiddleware,
  requireStepUp,
  [
    body('currentPin').optional({ checkFalsy: true }).isLength({ min: 6, max: 6 }).isNumeric(),
    pinField('newPin'),
  ],
  authController.updatePin
);

router.post('/mfa/recovery-codes/regenerate', authMiddleware, requireStepUp, authController.regenerateRecoveryCodes);
router.post('/mfa/totp/setup', authMiddleware, requireStepUp, authController.setupNewTotp);
router.post('/mfa/totp/confirm', authMiddleware, requireStepUp, [totpCodeField('totpCode')], authController.confirmNewTotp);
router.post('/sync-vault-data', authMiddleware, authController.syncVaultData);

module.exports = router;
