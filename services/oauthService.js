const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const PendingOAuthFlow = require('../models/PendingOAuthFlow');

const OAUTH_FLOW_TTL_MINUTES = parseInt(process.env.OAUTH_FLOW_TTL_MINUTES || '10', 10);
const OAUTH_STATE_SECRET = process.env.OAUTH_STATE_SECRET || process.env.JWT_SECRET;

const buildFlowExpiry = () => new Date(Date.now() + OAUTH_FLOW_TTL_MINUTES * 60 * 1000);

const getFrontendCallbackUrl = () => {
  return process.env.OAUTH_FRONTEND_CALLBACK_URL || `${process.env.FRONTEND_URL || 'http://localhost:3000'}/auth/callback`;
};

const createPendingOAuthFlow = async ({ provider, intent, userId = null, device = {} }) => {
  return PendingOAuthFlow.create({
    flowId: crypto.randomUUID(),
    provider,
    intent,
    userId,
    deviceId: device.deviceId || null,
    deviceName: device.deviceName || null,
    clientType: device.clientType || 'web',
    nonce: crypto.randomBytes(16).toString('hex'),
    expiresAt: buildFlowExpiry(),
  });
};

const getPendingOAuthFlow = async (flowId) => {
  if (!flowId) return null;
  const flow = await PendingOAuthFlow.findOne({ flowId });
  if (!flow) return null;
  if (new Date(flow.expiresAt).getTime() <= Date.now()) {
    await PendingOAuthFlow.deleteOne({ _id: flow._id });
    return null;
  }
  return flow;
};

const signOAuthState = ({ flowId, nonce }) => jwt.sign(
  { type: 'oauth-state', flowId, nonce },
  OAUTH_STATE_SECRET,
  { expiresIn: `${OAUTH_FLOW_TTL_MINUTES}m` }
);

const verifyOAuthState = (state) => {
  const decoded = jwt.verify(state, OAUTH_STATE_SECRET);
  if (decoded.type !== 'oauth-state') {
    throw new Error('Invalid OAuth state');
  }
  return decoded;
};

const setOAuthFlowResult = async (flow, resultType, resultPayload = {}) => {
  flow.resultType = resultType;
  flow.resultPayload = resultPayload;
  flow.consumedAt = null;
  flow.expiresAt = buildFlowExpiry();
  await flow.save();
  return flow;
};

const consumeOAuthFlowResult = async (flowId) => {
  const flow = await getPendingOAuthFlow(flowId);
  if (!flow || !flow.resultType) {
    return null;
  }

  if (flow.consumedAt) {
    return null;
  }

  flow.consumedAt = new Date();
  await flow.save();

  return {
    type: flow.resultType,
    provider: flow.provider,
    intent: flow.intent,
    ...flow.resultPayload,
  };
};

const buildFrontendRedirect = (flowId) => {
  const redirectUrl = new URL(getFrontendCallbackUrl());
  redirectUrl.searchParams.set('flow', flowId);
  return redirectUrl.toString();
};

const buildProviderAuthorizationPath = (provider, flowId, intent) => {
  const params = new URLSearchParams();
  if (intent) params.set('intent', intent);
  if (flowId) params.set('flow', flowId);
  return `/api/auth/${provider}?${params.toString()}`;
};

const resolveGithubVerifiedEmail = async (accessToken) => {
  const response = await fetch('https://api.github.com/user/emails', {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'FormOS',
    },
  });

  if (!response.ok) {
    throw new Error('Unable to load GitHub email addresses');
  }

  const emails = await response.json();
  const primaryVerified = emails.find((entry) => entry.primary && entry.verified);
  if (primaryVerified) return primaryVerified;
  return emails.find((entry) => entry.verified) || null;
};

module.exports = {
  buildProviderAuthorizationPath,
  buildFrontendRedirect,
  consumeOAuthFlowResult,
  createPendingOAuthFlow,
  getPendingOAuthFlow,
  resolveGithubVerifiedEmail,
  setOAuthFlowResult,
  signOAuthState,
  verifyOAuthState,
};
