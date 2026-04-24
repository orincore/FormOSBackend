const rateLimit = require('express-rate-limit');

const buildLimiter = (options) => rateLimit({
  standardHeaders: true,
  legacyHeaders: false,
  ...options,
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      message: options.message,
    });
  },
});

const signupStartLimiter = buildLimiter({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many registration attempts. Please try again shortly.',
});

const signupEmailVerifyLimiter = buildLimiter({
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: 'Too many email verification attempts. Please wait before retrying.',
});

const signupMfaVerifyLimiter = buildLimiter({
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: 'Too many authenticator verification attempts. Please wait before retrying.',
});

const loginLimiter = buildLimiter({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many login attempts. Please try again later.',
});

const loginMfaLimiter = buildLimiter({
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: 'Too many MFA verification attempts. Please wait before retrying.',
});

module.exports = {
  loginLimiter,
  loginMfaLimiter,
  signupEmailVerifyLimiter,
  signupMfaVerifyLimiter,
  signupStartLimiter,
};
