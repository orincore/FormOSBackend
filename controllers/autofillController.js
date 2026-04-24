const User = require('../models/User');
const ragService = require('../services/ragService');
const { splitAutofillPayload } = require('../services/securityService');

exports.getAutofillData = async (req, res) => {
  try {
    const user = await User.findById(req.userId);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    const includeSensitive = String(req.query.includeSensitive || '').toLowerCase() === 'true';

    if (includeSensitive && !req.stepUpVerified) {
      return res.status(403).json({
        success: false,
        code: 'STEP_UP_REQUIRED',
        message: 'Recent re-authentication is required before sensitive autofill.',
      });
    }

    const autofillData = await ragService.generateAutofillData(user);
    const payload = splitAutofillPayload(autofillData, includeSensitive);

    return res.json({
      success: true,
      ...payload,
      stepUpExpiresAt: req.authSession?.stepUpExpiresAt || null,
    });
  } catch (error) {
    console.error('Autofill error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error fetching autofill data',
    });
  }
};
