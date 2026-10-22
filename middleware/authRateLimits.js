const rateLimit = require('express-rate-limit');

// Limits exist to stop guessing, so successful requests are not counted
// (skipSuccessfulRequests) and each endpoint family has its own counter.
const buildLimiter = ({ message, skipSuccessfulRequests = false, ...options }) => rateLimit({
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests,
  ...options,
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      code: 'RATE_LIMITED',
      message,
    });
  },
});

const signupStartLimiter = buildLimiter({
  windowMs: 15 * 60 * 1000,
  max: 10,
  skipFailedRequests: true,
  message: 'Too many registration attempts. Please try again shortly.',
});

const signupResendLimiter = buildLimiter({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many code requests. Please wait a few minutes before requesting another code.',
});

const signupEmailVerifyLimiter = buildLimiter({
  windowMs: 10 * 60 * 1000,
  max: 10,
  skipSuccessfulRequests: true,
  message: 'Too many email verification attempts. Please wait before retrying.',
});

const signupMfaVerifyLimiter = buildLimiter({
  windowMs: 10 * 60 * 1000,
  max: 10,
  skipSuccessfulRequests: true,
  message: 'Too many authenticator verification attempts. Please wait before retrying.',
});

const loginLimiter = buildLimiter({
  windowMs: 15 * 60 * 1000,
  max: 10,
  skipSuccessfulRequests: true,
  message: 'Too many login attempts. Please try again later.',
});

const loginMfaLimiter = buildLimiter({
  windowMs: 10 * 60 * 1000,
  max: 10,
  skipSuccessfulRequests: true,
  message: 'Too many MFA verification attempts. Please wait before retrying.',
});

const otpRequestLimiter = buildLimiter({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many code requests. Please wait a few minutes before requesting another code.',
});

const passwordResetLimiter = buildLimiter({
  windowMs: 15 * 60 * 1000,
  max: 10,
  skipSuccessfulRequests: true,
  message: 'Too many reset attempts. Please try again later.',
});

const stepUpLimiter = buildLimiter({
  windowMs: 10 * 60 * 1000,
  max: 10,
  skipSuccessfulRequests: true,
  message: 'Too many re-authentication attempts. Please wait before retrying.',
});

const checkEmailLimiter = buildLimiter({
  windowMs: 5 * 60 * 1000,
  max: 60,
  message: 'Too many requests. Please slow down.',
});

const adminLoginLimiter = buildLimiter({
  windowMs: 15 * 60 * 1000,
  max: 8,
  skipSuccessfulRequests: true,
  message: 'Too many sign-in attempts. Wait a few minutes and try again.',
});

const adminLimiter = buildLimiter({
  windowMs: 10 * 60 * 1000,
  max: 600,
  message: 'Too many admin requests. Please slow down.',
});

const whatsappLinkLimiter = buildLimiter({
  windowMs: 60 * 60 * 1000,
  max: 8,
  message: 'Too many WhatsApp codes requested. Please try again in an hour.',
});

const whatsappVerifyLimiter = buildLimiter({
  windowMs: 15 * 60 * 1000,
  max: 12,
  skipSuccessfulRequests: true,
  message: 'Too many incorrect codes. Please wait a few minutes before trying again.',
});

module.exports = {
  whatsappLinkLimiter,
  whatsappVerifyLimiter,
  adminLimiter,
  adminLoginLimiter,
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
};
