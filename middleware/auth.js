const jwt = require('jsonwebtoken');
const User = require('../models/User');
const AuthSession = require('../models/AuthSession');
const { isStepUpValid, touchSession } = require('../services/sessionService');

const authMiddleware = async (req, res, next) => {
  try {
    // Get token from header
    const token = req.header('Authorization')?.replace('Bearer ', '');

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'No authentication token, access denied'
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (!decoded.sessionId) {
      return res.status(401).json({
        success: false,
        message: 'Session is not valid'
      });
    }
    
    // Find user
    const [user, session] = await Promise.all([
      User.findById(decoded.userId),
      AuthSession.findOne({
        sessionId: decoded.sessionId,
        userId: decoded.userId,
        revokedAt: null
      })
    ]);
    
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User not found'
      });
    }

    if (user.status === 'suspended') {
      return res.status(403).json({
        success: false,
        code: 'ACCOUNT_SUSPENDED',
        message: 'This account has been suspended. Contact support for help.',
      });
    }

    if (!user.isVerified || !user.emailVerifiedAt || !user.security?.mfa?.enabled) {
      console.log('DEBUG AUTH 403:', {
        email: user.email,
        isVerified: user.isVerified,
        emailVerifiedAt: user.emailVerifiedAt,
        mfaEnabled: user.security?.mfa?.enabled
      });
      return res.status(403).json({
        success: false,
        message: 'Account verification is incomplete'
      });
    }

    if (!session) {
      return res.status(401).json({
        success: false,
        message: 'Session has expired or was revoked'
      });
    }

    req.user = user;
    req.userId = decoded.userId;
    req.authSession = session;
    req.stepUpVerified = isStepUpValid(session);

    await touchSession(session);
    next();
  } catch (error) {
    res.status(401).json({
      success: false,
      message: 'Token is not valid'
    });
  }
};

module.exports = authMiddleware;
