const crypto = require('crypto');
const { validationResult } = require('express-validator');
const passport = require('passport');
const User = require('../models/User');
const PendingRegistration = require('../models/PendingRegistration');
const { findUserByEmail, releaseAbandonedAccount } = require('../services/accountService');
const { isProviderConfigured } = require('../config/passport');
const {
  buildQrCodeDataUrl,
  encryptText,
  generateMfaSecret,
  generateNumericOtp,
  getDeviceContext,
  hashValue,
  maskValueByField,
} = require('../services/securityService');
const { signLoginChallenge } = require('../services/sessionService');
const {
  buildFrontendRedirect,
  buildProviderAuthorizationPath,
  consumeOAuthFlowResult,
  createPendingOAuthFlow,
  getPendingOAuthFlow,
  setOAuthFlowResult,
  signOAuthState,
  verifyOAuthState,
} = require('../services/oauthService');

const REGISTRATION_TTL_MINUTES = parseInt(process.env.PENDING_REGISTRATION_TTL_MINUTES || '15', 10);

const buildRegistrationExpiry = () => new Date(Date.now() + REGISTRATION_TTL_MINUTES * 60 * 1000);

const getFrontendErrorRedirect = (message) => {
  const redirect = new URL('/login', process.env.FRONTEND_URL || 'http://localhost:3000');
  redirect.searchParams.set('oauthError', message);
  return redirect.toString();
};

const handleValidationErrors = (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(400).json({
      success: false,
      code: 'VALIDATION_FAILED',
      message: errors.array()[0]?.msg || 'Invalid request',
      errors: errors.array(),
    });
    return true;
  }
  return false;
};

const getEffectiveAuthMethods = (user) => ({
  localPin: !!(user?.authMethods?.localPin ?? user?.pin),
  google: !!(user?.authMethods?.google ?? user?.providers?.google?.providerId),
  github: !!(user?.authMethods?.github ?? user?.providers?.github?.providerId),
});

const ensureOAuthLoginReadyUser = (user) => {
  return !!(
    user &&
    user.isVerified &&
    user.emailVerifiedAt &&
    user.security?.mfa?.enabled &&
    user.security?.mfa?.secretEncrypted &&
    user.security?.mfa?.secretIv &&
    user.security?.mfa?.secretAuthTag
  );
};

const getProviderFields = (provider, identity) => (
  provider === 'google'
    ? {
        google: {
          providerId: identity.providerId,
          email: identity.email,
          emailVerified: !!identity.emailVerified,
          linkedAt: new Date(),
          lastLoginAt: new Date(),
          avatarUrl: identity.avatarUrl || null,
        },
      }
    : {
        github: {
          providerId: identity.providerId,
          username: identity.username || null,
          email: identity.email,
          emailVerified: !!identity.emailVerified,
          linkedAt: new Date(),
          lastLoginAt: new Date(),
          avatarUrl: identity.avatarUrl || null,
          profileUrl: identity.profileUrl || null,
        },
      }
);

// Set only this provider's sub-document. Rebuilding the whole `providers` object from a
// spread Mongoose document produced invalid values and broke OAuth for linked users.
const applyProviderFields = (user, provider, identity) => {
  user.set(`providers.${provider}`, getProviderFields(provider, identity)[provider]);
};

const buildAuthMethodsUpdate = (provider, user) => {
  const current = getEffectiveAuthMethods(user);
  return {
    localPin: current.localPin,
    google: provider === 'google' ? true : current.google,
    github: provider === 'github' ? true : current.github,
  };
};

const buildPendingRegistrationFromOAuth = async (identity) => {
  const secret = generateMfaSecret(identity.email);
  const encryptedSecret = encryptText(secret.base32);
  const placeholderCodeHash = await hashValue(generateNumericOtp(6));

  const pending = await PendingRegistration.findOneAndUpdate(
    { email: identity.email },
    {
      email: identity.email,
      name: identity.name,
      phone: '',
      authMode: 'oauth',
      pinHash: null,
      emailVerificationCodeHash: placeholderCodeHash,
      emailVerificationExpiresAt: buildRegistrationExpiry(),
      emailVerificationSentAt: new Date(),
      emailVerifiedAt: new Date(),
      security: {
        mfa: {
          secretEncrypted: encryptedSecret.encrypted,
          secretIv: encryptedSecret.iv,
          secretAuthTag: encryptedSecret.authTag,
          verifiedAt: null,
        },
        recoveryCodeHashes: [],
        recoveryCodesGeneratedAt: null,
        recoveryCodesConfirmedAt: null,
      },
      oauth: {
        provider: identity.provider,
        providerId: identity.providerId,
        providerEmail: identity.email,
        providerEmailVerified: !!identity.emailVerified,
        providerUsername: identity.username || null,
        avatarUrl: identity.avatarUrl || null,
        profileUrl: identity.profileUrl || null,
      },
      expiresAt: buildRegistrationExpiry(),
    },
    {
      upsert: true,
      new: true,
      setDefaultsOnInsert: true,
    }
  );

  return {
    registrationId: pending._id,
    nextStep: 'setup_mfa',
    maskedEmail: maskValueByField('email', pending.email),
    expiresAt: pending.expiresAt,
    secret: secret.base32,
    qrCodeDataUrl: await buildQrCodeDataUrl(secret.otpauth_url),
    message: `${identity.provider === 'google' ? 'Google' : 'GitHub'} sign-in verified. Set up your authenticator app to finish creating the account.`,
  };
};

// A verified provider sign-in for an account that is ready to use: link the provider if it is new, then hand the browser
// a login challenge. The password-less part ends here: the authenticator code is still required to get a session.
const continueToMfa = async (flow, res, user, provider, identity) => {
  if (user.status === 'suspended') {
    return finalizeFlowWithError(flow, res, 'This account has been suspended. Contact support for help.');
  }

  if (!ensureOAuthLoginReadyUser(user)) {
    return finalizeFlowWithError(
      flow,
      res,
      'This account has not finished email verification and mandatory MFA enrollment yet. Complete setup with your existing sign-in method before using OAuth.'
    );
  }

  applyProviderFields(user, provider, identity);
  user.authMethods = buildAuthMethodsUpdate(provider, user);
  await user.save();

  await setOAuthFlowResult(flow, 'mfa', {
    provider,
    challengeToken: signLoginChallenge({
      userId: user._id.toString(),
      deviceId: flow.deviceId,
      deviceName: flow.deviceName,
      clientType: flow.clientType,
      trustDevice: false,
      authMethod: provider,
    }),
    message: `${provider === 'google' ? 'Google' : 'GitHub'} sign-in verified. Enter your authenticator code to continue.`,
  });

  return res.redirect(buildFrontendRedirect(flow.flowId));
};

const finalizeFlowWithError = async (flow, res, message) => {
  if (flow) {
    await setOAuthFlowResult(flow, 'error', { message });
    return res.redirect(buildFrontendRedirect(flow.flowId));
  }

  return res.redirect(getFrontendErrorRedirect(message));
};

const resolveFlowForStart = async (req, provider) => {
  const requestedIntent = ['login', 'signup', 'link'].includes(req.query.intent)
    ? req.query.intent
    : 'login';
  const existingFlowId = typeof req.query.flow === 'string' ? req.query.flow : null;

  if (existingFlowId) {
    const existingFlow = await getPendingOAuthFlow(existingFlowId);
    if (!existingFlow || existingFlow.provider !== provider || existingFlow.intent !== requestedIntent) {
      return null;
    }
    return existingFlow;
  }

  if (requestedIntent === 'link') {
    return null;
  }

  return createPendingOAuthFlow({
    provider,
    intent: requestedIntent,
    device: getDeviceContext(req),
  });
};

const startProviderAuth = (provider, strategyName, options) => async (req, res, next) => {
  try {
    if (!isProviderConfigured(provider)) {
      return res.redirect(getFrontendErrorRedirect(`${provider === 'google' ? 'Google' : 'GitHub'} OAuth is not configured yet.`));
    }

    const flow = await resolveFlowForStart(req, provider);
    if (!flow) {
      return res.redirect(getFrontendErrorRedirect(`Unable to start ${provider} sign-in.`));
    }

    const state = signOAuthState({ flowId: flow.flowId, nonce: flow.nonce });
    return passport.authenticate(strategyName, {
      session: false,
      state,
      ...options,
    })(req, res, next);
  } catch (error) {
    return res.redirect(getFrontendErrorRedirect(`Unable to start ${provider} sign-in.`));
  }
};

const providerCallback = (strategyName, provider) => (req, res, next) => {
  passport.authenticate(strategyName, { session: false }, async (error, identity) => {
    let flow = null;

    try {
      if (!isProviderConfigured(provider)) {
        return finalizeFlowWithError(null, res, `${provider === 'google' ? 'Google' : 'GitHub'} OAuth is not configured yet.`);
      }

      const statePayload = verifyOAuthState(String(req.query.state || ''));
      flow = await getPendingOAuthFlow(statePayload.flowId);
      if (!flow || flow.provider !== provider || flow.nonce !== statePayload.nonce) {
        return finalizeFlowWithError(null, res, 'OAuth flow is invalid or expired. Please try again.');
      }

      if (error || !identity) {
        return finalizeFlowWithError(flow, res, `Unable to complete ${provider} sign-in.`);
      }

      const linkedUser = await User.findOne({ [`providers.${provider}.providerId`]: identity.providerId });

      if (flow.intent === 'link') {
        const currentUser = await User.findById(flow.userId);
        if (!currentUser) {
          return finalizeFlowWithError(flow, res, 'Your session expired before the account could be linked.');
        }

        if (linkedUser && String(linkedUser._id) !== String(currentUser._id)) {
          return finalizeFlowWithError(flow, res, `That ${provider} account is already linked to another FormOS user.`);
        }

        if (currentUser.providers?.[provider]?.providerId) {
          return finalizeFlowWithError(flow, res, `Your account is already linked to ${provider}.`);
        }

        applyProviderFields(currentUser, provider, identity);
        currentUser.authMethods = buildAuthMethodsUpdate(provider, currentUser);
        await currentUser.save();

        await setOAuthFlowResult(flow, 'linked', {
          provider,
          message: `${provider === 'google' ? 'Google' : 'GitHub'} account linked successfully.`,
        });

        return res.redirect(buildFrontendRedirect(flow.flowId));
      }

      if (linkedUser) {
        return continueToMfa(flow, res, linkedUser, provider, identity);
      }

      if (!identity.email || !identity.emailVerified) {
        return finalizeFlowWithError(
          flow,
          res,
          provider === 'github'
            ? 'GitHub did not provide a verified email address. Sign up with email first, then link GitHub from Settings.'
            : 'A verified provider email is required to continue.'
        );
      }

      const existingUser = await findUserByEmail(identity.email);
      if (!(await releaseAbandonedAccount(existingUser))) {
        // The provider has verified this email address, and the account with that email is this person's. Link the
        // provider and continue to the authenticator step, as a normal sign-in would.
        const otherAccount = existingUser.providers?.[provider]?.providerId;
        if (otherAccount && otherAccount !== identity.providerId) {
          return finalizeFlowWithError(
            flow,
            res,
            `A different ${provider === 'google' ? 'Google' : 'GitHub'} account is already linked to ${identity.email}. Sign in with that one, or with your PIN.`
          );
        }
        return continueToMfa(flow, res, existingUser, provider, identity);
      }

      const signupPayload = await buildPendingRegistrationFromOAuth(identity);
      await setOAuthFlowResult(flow, 'signup', {
        provider,
        ...signupPayload,
      });

      return res.redirect(buildFrontendRedirect(flow.flowId));
    } catch (callbackError) {
      console.error(`OAuth ${provider} callback error:`, callbackError.message);
      return finalizeFlowWithError(flow, res, `Unable to complete ${provider} sign-in right now.`);
    }
  })(req, res, next);
};

exports.startGoogle = startProviderAuth('google', 'google', {
  scope: ['openid', 'profile', 'email'],
});

exports.startGitHub = startProviderAuth('github', 'github', {
  scope: ['read:user', 'user:email'],
});

exports.googleCallback = providerCallback('google', 'google');
exports.githubCallback = providerCallback('github', 'github');

exports.startLink = async (req, res) => {
  if (handleValidationErrors(req, res)) return;

  const provider = String(req.body.provider || '');
  if (!['google', 'github'].includes(provider)) {
    return res.status(400).json({
      success: false,
      message: 'A supported OAuth provider is required.',
    });
  }

  const flow = await createPendingOAuthFlow({
    provider,
    intent: 'link',
    userId: req.userId,
    device: getDeviceContext(req),
  });

  return res.json({
    success: true,
    authorizationUrl: buildProviderAuthorizationPath(provider, flow.flowId, 'link'),
  });
};

exports.consumeResult = async (req, res) => {
  if (handleValidationErrors(req, res)) return;

  const result = await consumeOAuthFlowResult(String(req.body.flow || ''));
  if (!result) {
    return res.status(400).json({
      success: false,
      message: 'OAuth result is invalid, expired, or already used.',
    });
  }

  return res.json({
    success: true,
    ...result,
  });
};

exports.unlinkProvider = async (req, res) => {
  const provider = String(req.params.provider || '');
  if (!['google', 'github'].includes(provider)) {
    return res.status(400).json({
      success: false,
      message: 'Unsupported OAuth provider.',
    });
  }

  if (!req.user.providers?.[provider]?.providerId) {
    return res.status(400).json({
      success: false,
      message: `${provider === 'google' ? 'Google' : 'GitHub'} is not linked to this account.`,
    });
  }

  const usableMethods = [
    !!(req.user.authMethods?.localPin ?? req.user.pin),
    !!req.user.providers?.google?.providerId,
    !!req.user.providers?.github?.providerId,
  ].filter(Boolean).length;

  if (usableMethods <= 1) {
    return res.status(400).json({
      success: false,
      message: 'You cannot unlink the last available sign-in method.',
    });
  }

  req.user.set(`providers.${provider}`, undefined);
  const remainingMethods = getEffectiveAuthMethods(req.user);
  req.user.authMethods = {
    localPin: remainingMethods.localPin,
    google: provider === 'google' ? false : remainingMethods.google,
    github: provider === 'github' ? false : remainingMethods.github,
  };
  await req.user.save();

  return res.json({
    success: true,
    message: `${provider === 'google' ? 'Google' : 'GitHub'} account unlinked successfully.`,
  });
};
