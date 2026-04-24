const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const AuthSession = require('../models/AuthSession');
const { buildStepUpExpiry, buildTrustedUntil, getDeviceContext } = require('./securityService');

const SESSION_TTL_DAYS = parseInt(process.env.SESSION_TTL_DAYS || '30', 10);
const TOUCH_SESSION_INTERVAL_MS = 5 * 60 * 1000;

const createAccessToken = (userId, sessionId) => {
  return jwt.sign({ userId, sessionId }, process.env.JWT_SECRET, {
    expiresIn: `${SESSION_TTL_DAYS}d`,
  });
};

const signLoginChallenge = ({ userId, deviceId, trustDevice, deviceName, clientType, authMethod = 'local' }) => {
  return jwt.sign(
    {
      type: 'login-mfa',
      userId,
      deviceId,
      trustDevice: !!trustDevice,
      deviceName,
      clientType,
      authMethod,
    },
    process.env.JWT_SECRET,
    { expiresIn: '10m' }
  );
};

const verifyLoginChallenge = (challengeToken) => {
  try {
    const decoded = jwt.verify(challengeToken, process.env.JWT_SECRET);
    if (decoded.type !== 'login-mfa') {
      const error = new Error('Invalid login challenge');
      error.code = 'LOGIN_CHALLENGE_INVALID';
      error.status = 400;
      throw error;
    }
    return decoded;
  } catch (error) {
    if (error.code === 'LOGIN_CHALLENGE_INVALID') {
      throw error;
    }

    if (error.name === 'TokenExpiredError') {
      const expiredError = new Error('Login challenge expired');
      expiredError.code = 'LOGIN_CHALLENGE_EXPIRED';
      expiredError.status = 400;
      throw expiredError;
    }

    const invalidError = new Error('Login challenge is invalid');
    invalidError.code = 'LOGIN_CHALLENGE_INVALID';
    invalidError.status = 400;
    throw invalidError;
  }
};

const createSession = async (userId, req, options = {}) => {
  const device = getDeviceContext(req);
  const now = new Date();
  const sessionId = crypto.randomUUID();

  const session = await AuthSession.create({
    sessionId,
    userId,
    deviceId: options.deviceId || device.deviceId,
    deviceName: options.deviceName || device.deviceName,
    clientType: options.clientType || device.clientType || 'web',
    userAgent: device.userAgent,
    ipHash: device.ipHash,
    trustedUntil: options.trustDevice ? buildTrustedUntil(options.trustedDays) : null,
    lastAuthenticatedAt: now,
    lastStepUpAt: now,
    stepUpExpiresAt: buildStepUpExpiry(),
    lastSeenAt: now,
    revokedAt: null,
    revokedReason: null,
  });

  return session;
};

const getTrustedDeviceSession = async (userId, deviceId) => {
  if (!deviceId) return null;

  return AuthSession.findOne({
    userId,
    deviceId,
    revokedAt: null,
    trustedUntil: { $gt: new Date() },
  }).sort({ trustedUntil: -1, lastSeenAt: -1 });
};

const markStepUpVerified = async (session) => {
  session.lastStepUpAt = new Date();
  session.stepUpExpiresAt = buildStepUpExpiry();
  await session.save();
  return session;
};

const revokeSession = async (session, reason = 'manual_logout') => {
  session.revokedAt = new Date();
  session.revokedReason = reason;
  session.trustedUntil = null;
  await session.save();
  return session;
};

const revokeOtherSessions = async (userId, currentSessionId) => {
  return AuthSession.updateMany(
    {
      userId,
      sessionId: { $ne: currentSessionId },
      revokedAt: null,
    },
    {
      $set: {
        revokedAt: new Date(),
        revokedReason: 'logout_other_sessions',
        trustedUntil: null,
      },
    }
  );
};

const revokeAllSessions = async (userId) => {
  return AuthSession.updateMany(
    { userId, revokedAt: null },
    {
      $set: {
        revokedAt: new Date(),
        revokedReason: 'logout_all_sessions',
        trustedUntil: null,
      },
    }
  );
};

const touchSession = async (session) => {
  if (!session?.lastSeenAt) return;
  if (Date.now() - new Date(session.lastSeenAt).getTime() < TOUCH_SESSION_INTERVAL_MS) return;
  session.lastSeenAt = new Date();
  await session.save();
};

const isStepUpValid = (session) => {
  return !!(session?.stepUpExpiresAt && new Date(session.stepUpExpiresAt).getTime() > Date.now());
};

const formatSessionForClient = (session, currentSessionId) => ({
  id: session.sessionId,
  deviceId: session.deviceId,
  deviceName: session.deviceName,
  clientType: session.clientType,
  trustedUntil: session.trustedUntil,
  lastSeenAt: session.lastSeenAt,
  createdAt: session.createdAt,
  isCurrent: session.sessionId === currentSessionId,
});

module.exports = {
  createAccessToken,
  createSession,
  formatSessionForClient,
  getTrustedDeviceSession,
  isStepUpValid,
  markStepUpVerified,
  revokeAllSessions,
  revokeOtherSessions,
  revokeSession,
  signLoginChallenge,
  touchSession,
  verifyLoginChallenge,
};
