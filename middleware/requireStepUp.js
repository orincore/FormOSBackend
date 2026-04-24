const { isStepUpValid } = require('../services/sessionService');

const requireStepUp = (req, res, next) => {
  if (!req.authSession || !isStepUpValid(req.authSession)) {
    return res.status(403).json({
      success: false,
      code: 'STEP_UP_REQUIRED',
      message: 'Recent re-authentication is required for this action.',
    });
  }

  return next();
};

module.exports = requireStepUp;
