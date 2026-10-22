const { validationResult } = require('express-validator');
const User = require('../models/User');
const AuthSession = require('../models/AuthSession');
const PendingRegistration = require('../models/PendingRegistration');
const LoginOtpChallenge = require('../models/LoginOtpChallenge');
const PasswordReset = require('../models/PasswordReset');
const AdminAuditLog = require('../models/AdminAuditLog');
const { canonicalEmail, emailCandidates, findUserByEmail, releaseAbandonedAccount } = require('../services/accountService');
const { sendVerificationEmail, sendPasswordResetEmail } = require('../services/emailService');
const {
  buildOtpauthUrl,
  buildQrCodeDataUrl,
  compareAdminPassword,
  compareHashedValue,
  consumeRecoveryCode,
  createRecoveryCodes,
  decryptText,
  encryptText,
  generateMfaSecret,
  generateNumericOtp,
  getClientIp,
  getDeviceContext,
  hashIpAddress,
  hashValue,
  maskStructuredData,
  maskValueByField,
  verifyTotp,
} = require('../services/securityService');
const {
  createAccessToken,
  createSession,
  formatSessionForClient,
  markStepUpVerified,
  revokeAllSessions,
  revokeOtherSessions,
  revokeSession,
  signLoginChallenge,
  verifyLoginChallenge,
} = require('../services/sessionService');

const REGISTRATION_TTL_MINUTES = parseInt(process.env.PENDING_REGISTRATION_TTL_MINUTES || '15', 10);

const handleValidationErrors = (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const first = errors.array()[0];
    res.status(400).json({
      success: false,
      code: 'VALIDATION_FAILED',
      message: first?.msg && first.msg !== 'Invalid value'
        ? first.msg
        : `Please check the ${first?.path || 'submitted'} field and try again.`,
      errors: errors.array(),
    });
    return true;
  }
  return false;
};

const buildRegistrationExpiry = () => new Date(Date.now() + REGISTRATION_TTL_MINUTES * 60 * 1000);

const getEffectiveAuthMethods = (user) => ({
  localPin: !!(user.authMethods?.localPin ?? user.pin),
  google: !!(user.authMethods?.google ?? user.providers?.google?.providerId),
  github: !!(user.authMethods?.github ?? user.providers?.github?.providerId),
});

const buildMaskedUser = (user, session = null) => {
  const isV2 = user.securityVersion === 2;
  return {
    id: user._id,
    email: user.email,
    name: user.name,
    phone: user.phone || '',
    isVerified: !!user.isVerified,
    role: user.role || 'user',
    status: user.status || 'active',
    extractedData: isV2 ? {} : maskStructuredData(user.extractedData || {}),
    security: {
      mfaEnabled: !!user.security?.mfa?.enabled,
      mfaRequired: true,
      recoveryCodesRemaining: user.security?.mfa?.backupCodeHashes?.length || 0,
      mfaResetRequired: !!user.security?.mfa?.resetRequired,
    },
    authMethods: getEffectiveAuthMethods(user),
    providers: {
      google: {
        linked: !!user.providers?.google?.providerId,
        email: user.providers?.google?.email || '',
        linkedAt: user.providers?.google?.linkedAt || null,
      },
      github: {
        linked: !!user.providers?.github?.providerId,
        email: user.providers?.github?.email || '',
        username: user.providers?.github?.username || '',
        linkedAt: user.providers?.github?.linkedAt || null,
      },
    },
    stepUp: {
      verified: !!(session?.stepUpExpiresAt && new Date(session.stepUpExpiresAt).getTime() > Date.now()),
      expiresAt: session?.stepUpExpiresAt || null,
    },
    ...(isV2 ? {
      encryptedProfile: user.encryptedProfile || null,
      userSalt: user.userSalt || null,
      wrappedUserKey: user.wrappedUserKey || null,
      securityVersion: 2,
    } : {
      securityVersion: 1,
    }),
  };
};

const buildFullUser = (user, session = null) => {
  const isV2 = user.securityVersion === 2;
  return {
    ...buildMaskedUser(user, session),
    extractedData: isV2 ? {} : (user.extractedData || {}),
  };
};

const buildAuthResponse = (user, session) => ({
  success: true,
  token: createAccessToken(user._id, session.sessionId),
  user: buildMaskedUser(user, session),
  session: formatSessionForClient(session, session.sessionId),
});

exports.buildAuthResponse = (...args) => buildAuthResponse(...args);
exports.buildMaskedUser = (...args) => buildMaskedUser(...args);

const getPendingRegistration = async (registrationId) => {
  if (!registrationId) return null;
  const pending = await PendingRegistration.findById(registrationId);
  if (!pending) return null;
  if (new Date(pending.expiresAt).getTime() <= Date.now()) {
    await PendingRegistration.deleteOne({ _id: pending._id });
    return null;
  }
  return pending;
};

const ensureActiveVerifiedMfaUser = (user) => {
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

const buildStoredTotpSecret = (mfaState = {}) => decryptText({
  encrypted: mfaState.secretEncrypted,
  iv: mfaState.secretIv,
  authTag: mfaState.secretAuthTag,
});

const SUSPENDED_RESPONSE = {
  success: false,
  code: 'ACCOUNT_SUSPENDED',
  message: 'This account has been suspended. Contact support for help.',
};

const MFA_FAILURES = {
  RESET_REQUIRED: {
    status: 403,
    code: 'MFA_RESET_REQUIRED',
    message: 'Your authenticator was reset by an administrator. Sign in with an email code, then set up a new authenticator.',
  },
  SECRET_UNREADABLE: {
    status: 409,
    code: 'MFA_SECRET_UNREADABLE',
    message: 'Your authenticator secret can no longer be read. Sign in with a recovery code, then set up your authenticator again.',
  },
  CODE_REUSED: {
    status: 401,
    code: 'MFA_CODE_REUSED',
    message: 'That code was already used. Wait for your app to show the next code and try again.',
  },
  INVALID: {
    status: 401,
    code: 'MFA_INVALID_CODE',
    message: 'Invalid MFA code',
  },
};

const mfaFailure = (reason) => MFA_FAILURES[reason] || MFA_FAILURES.INVALID;

// Verifies a TOTP or recovery code. Every accepted credential is consumed with an
// atomic conditional update so two concurrent requests cannot both succeed with it.
const verifyMfaAttempt = async (user, { totpCode, recoveryCode }) => {
  if (!ensureActiveVerifiedMfaUser(user)) {
    return { verified: false, reason: 'INVALID' };
  }

  const mfa = user.security.mfa;
  if (mfa.resetRequired) {
    return { verified: false, reason: 'RESET_REQUIRED' };
  }
  let reason = 'INVALID';

  if (totpCode) {
    let secret = null;
    try {
      secret = buildStoredTotpSecret(mfa);
    } catch (error) {
      if (error.code !== 'MFA_SECRET_DECRYPT_FAILED') throw error;
      console.error(`MFA secret for user ${user._id} cannot be decrypted with the configured keys`);
      reason = 'SECRET_UNREADABLE';
    }

    if (secret) {
      const result = verifyTotp(secret, totpCode, mfa.lastUsedTotpStep);
      if (result.valid) {
        const claimed = await User.updateOne(
          {
            _id: user._id,
            $or: [
              { 'security.mfa.lastUsedTotpStep': null },
              { 'security.mfa.lastUsedTotpStep': { $lt: result.step } },
            ],
          },
          {
            $set: {
              'security.mfa.lastUsedTotpStep': result.step,
              'security.mfa.lastVerifiedAt': new Date(),
            },
          }
        );
        if (claimed.modifiedCount === 1) {
          mfa.lastUsedTotpStep = result.step;
          return { verified: true, method: 'totp' };
        }
        reason = 'CODE_REUSED';
      } else if (result.replayed) {
        reason = 'CODE_REUSED';
      }
    }
  }

  if (recoveryCode) {
    const hashes = mfa.backupCodeHashes || [];
    const { matched, remainingHashes } = await consumeRecoveryCode(recoveryCode, hashes);

    if (matched) {
      const usedHash = hashes.find((hash) => !remainingHashes.includes(hash));
      const consumed = await User.updateOne(
        { _id: user._id, 'security.mfa.backupCodeHashes': usedHash },
        {
          $pull: { 'security.mfa.backupCodeHashes': usedHash },
          $set: { 'security.mfa.lastVerifiedAt': new Date() },
        }
      );
      if (consumed.modifiedCount === 1) {
        mfa.backupCodeHashes = remainingHashes;
        return { verified: true, method: 'recovery_code' };
      }
    }
  }

  return { verified: false, reason };
};

exports.startSignup = async (req, res) => {
  try {
    if (handleValidationErrors(req, res)) return;

    const email = canonicalEmail(req.body.email);
    const { name, pin, phone, securityVersion, userSalt, recoverySalt, wrappedUserKey, wrappedUserKeyRecovery } = req.body;

    const existingUser = await findUserByEmail(email);
    if (!(await releaseAbandonedAccount(existingUser))) {
      return res.status(400).json({
        success: false,
        code: 'EMAIL_TAKEN',
        message: 'An account already exists with this email',
      });
    }

    if (phone) {
      const phoneOwner = await User.findOne({ phone });
      if (phoneOwner) {
        return res.status(400).json({
          success: false,
          code: 'PHONE_TAKEN',
          message: 'This phone number is already linked to another account',
        });
      }
    }

    const otpCode = generateNumericOtp(6);
    const pendingRegistration = await PendingRegistration.findOneAndUpdate(
      { email },
      {
        email,
        name,
        phone: phone || '',
        authMode: 'local',
        securityVersion: securityVersion || 1,
        userSalt: userSalt || null,
        recoverySalt: recoverySalt || null,
        wrappedUserKey: wrappedUserKey || null,
        wrappedUserKeyRecovery: wrappedUserKeyRecovery || null,
        pinHash: await hashValue(pin),
        emailVerificationCodeHash: await hashValue(otpCode),
        emailVerificationExpiresAt: buildRegistrationExpiry(),
        emailVerificationSentAt: new Date(),
        emailVerifiedAt: null,
        security: {
          mfa: {
            secretEncrypted: null,
            secretIv: null,
            secretAuthTag: null,
            verifiedAt: null,
          },
          recoveryCodeHashes: [],
          recoveryCodesGeneratedAt: null,
          recoveryCodesConfirmedAt: null,
        },
        expiresAt: buildRegistrationExpiry(),
      },
      {
        upsert: true,
        new: true,
        setDefaultsOnInsert: true,
      }
    );

    await sendVerificationEmail({
      email,
      name,
      code: otpCode,
      expiresInMinutes: REGISTRATION_TTL_MINUTES,
    });

    return res.status(201).json({
      success: true,
      registrationId: pendingRegistration._id,
      nextStep: 'verify_email',
      maskedEmail: maskValueByField('email', email),
      expiresAt: pendingRegistration.expiresAt,
      message: 'Verification code sent. Complete email verification to continue.',
    });
  } catch (error) {
    console.error('Start signup error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Unable to start registration',
    });
  }
};

exports.resendSignupEmailCode = async (req, res) => {
  try {
    if (handleValidationErrors(req, res)) return;

    const pending = await getPendingRegistration(req.body.registrationId);
    if (!pending) {
      return res.status(404).json({
        success: false,
        message: 'Registration expired. Please start again.',
      });
    }

    if (pending.emailVerifiedAt) {
      return res.status(400).json({
        success: false,
        message: 'Email is already verified for this registration.',
      });
    }

    const otpCode = generateNumericOtp(6);
    pending.emailVerificationCodeHash = await hashValue(otpCode);
    pending.emailVerificationExpiresAt = buildRegistrationExpiry();
    pending.emailVerificationSentAt = new Date();
    pending.expiresAt = buildRegistrationExpiry();
    await pending.save();

    await sendVerificationEmail({
      email: pending.email,
      name: pending.name,
      code: otpCode,
      expiresInMinutes: REGISTRATION_TTL_MINUTES,
    });

    return res.json({
      success: true,
      message: 'A new verification code was sent.',
      expiresAt: pending.expiresAt,
      maskedEmail: maskValueByField('email', pending.email),
    });
  } catch (error) {
    console.error('Resend signup email error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Unable to resend verification code',
    });
  }
};

exports.verifySignupEmail = async (req, res) => {
  try {
    if (handleValidationErrors(req, res)) return;

    const pending = await getPendingRegistration(req.body.registrationId);
    if (!pending) {
      return res.status(404).json({
        success: false,
        message: 'Registration expired. Please start again.',
      });
    }

    if (!(await compareHashedValue(String(req.body.emailCode || ''), pending.emailVerificationCodeHash))) {
      return res.status(400).json({
        success: false,
        message: 'Invalid verification code',
      });
    }

    if (new Date(pending.emailVerificationExpiresAt).getTime() <= Date.now()) {
      return res.status(400).json({
        success: false,
        message: 'Verification code has expired. Request a new one.',
      });
    }

    if (pending.security?.mfa?.verifiedAt) {
      return res.status(400).json({
        success: false,
        message: 'Authenticator is already verified for this registration. Continue to the recovery codes.',
      });
    }

    // Re-use the secret if one was already issued for this registration. Issuing a
    // new one on every call would invalidate the QR code the user has already scanned.
    let secretBase32;
    if (pending.security?.mfa?.secretEncrypted) {
      secretBase32 = buildStoredTotpSecret(pending.security.mfa);
    } else {
      const secret = generateMfaSecret(pending.email);
      const encryptedSecret = encryptText(secret.base32);
      secretBase32 = secret.base32;
      pending.security.mfa.secretEncrypted = encryptedSecret.encrypted;
      pending.security.mfa.secretIv = encryptedSecret.iv;
      pending.security.mfa.secretAuthTag = encryptedSecret.authTag;
    }

    pending.emailVerifiedAt = pending.emailVerifiedAt || new Date();
    pending.expiresAt = buildRegistrationExpiry();
    await pending.save();

    return res.json({
      success: true,
      registrationId: pending._id,
      nextStep: 'setup_mfa',
      maskedEmail: maskValueByField('email', pending.email),
      expiresAt: pending.expiresAt,
      secret: secretBase32,
      qrCodeDataUrl: await buildQrCodeDataUrl(buildOtpauthUrl(pending.email, secretBase32)),
      message: 'Email verified. Scan the QR code with your authenticator app to continue.',
    });
  } catch (error) {
    console.error('Verify signup email error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Unable to verify email',
    });
  }
};

exports.verifySignupMfa = async (req, res) => {
  try {
    if (handleValidationErrors(req, res)) return;

    const pending = await getPendingRegistration(req.body.registrationId);
    if (!pending) {
      return res.status(404).json({
        success: false,
        message: 'Registration expired. Please start again.',
      });
    }

    if (!pending.emailVerifiedAt) {
      return res.status(400).json({
        success: false,
        message: 'Verify your email before setting up MFA.',
      });
    }

    const secret = buildStoredTotpSecret(pending.security?.mfa);
    const totpResult = verifyTotp(secret, req.body.totpCode);
    if (!totpResult.valid) {
      return res.status(400).json({
        success: false,
        code: 'MFA_INVALID_CODE',
        message: 'Invalid authenticator code. Make sure you scanned the QR code shown on this page and that your phone time is set automatically.',
      });
    }

    const recoveryCodes = await createRecoveryCodes();
    pending.security.mfa.lastUsedTotpStep = totpResult.step;
    pending.security.mfa.verifiedAt = new Date();
    pending.security.recoveryCodeHashes = recoveryCodes.hashedCodes;
    pending.security.recoveryCodesGeneratedAt = new Date();
    pending.security.recoveryCodesConfirmedAt = null;
    pending.expiresAt = buildRegistrationExpiry();
    await pending.save();

    return res.json({
      success: true,
      registrationId: pending._id,
      nextStep: 'confirm_recovery_codes',
      expiresAt: pending.expiresAt,
      recoveryCodes: recoveryCodes.plainCodes,
      message: 'Authenticator verified. Save your recovery codes before activating the account.',
    });
  } catch (error) {
    console.error('Verify signup MFA error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Unable to verify authenticator code',
    });
  }
};

exports.completeSignup = async (req, res) => {
  try {
    if (handleValidationErrors(req, res)) return;

    const pending = await getPendingRegistration(req.body.registrationId);
    if (!pending) {
      return res.status(404).json({
        success: false,
        message: 'Registration expired. Please start again.',
      });
    }

    if (!pending.emailVerifiedAt || !pending.security?.mfa?.verifiedAt) {
      return res.status(400).json({
        success: false,
        message: 'Complete email verification and authenticator setup first.',
      });
    }

    if (!req.body.recoveryCodesConfirmed) {
      return res.status(400).json({
        success: false,
        message: 'You must confirm that you saved the recovery codes.',
      });
    }

    const existingUser = await findUserByEmail(pending.email);
    if (existingUser) {
      await PendingRegistration.deleteOne({ _id: pending._id });
      return res.status(400).json({
        success: false,
        message: 'An account already exists with this email',
      });
    }

    if (pending.authMode === 'local' && !pending.pinHash) {
      return res.status(400).json({
        success: false,
        message: 'Registration data is invalid. Please restart signup.',
      });
    }

    pending.security.recoveryCodesConfirmedAt = new Date();

    const userPayload = {
      email: pending.email,
      name: pending.name,
      phone: pending.phone || undefined,
      isVerified: true,
      emailVerifiedAt: pending.emailVerifiedAt,
      security: {
        mfa: {
          enabled: true,
          secretEncrypted: pending.security.mfa.secretEncrypted,
          secretIv: pending.security.mfa.secretIv,
          secretAuthTag: pending.security.mfa.secretAuthTag,
          backupCodeHashes: pending.security.recoveryCodeHashes,
          enabledAt: pending.security.mfa.verifiedAt,
          lastVerifiedAt: pending.security.mfa.verifiedAt,
          lastUsedTotpStep: pending.security.mfa.lastUsedTotpStep ?? null,
          recoveryCodesGeneratedAt: pending.security.recoveryCodesGeneratedAt,
        },
      },
      authMethods: {
        localPin: pending.authMode === 'local',
        google: pending.oauth?.provider === 'google',
        github: pending.oauth?.provider === 'github',
      },
      providers: pending.oauth?.provider === 'google'
        ? {
            google: {
              providerId: pending.oauth.providerId,
              email: pending.oauth.providerEmail || pending.email,
              emailVerified: !!pending.oauth.providerEmailVerified,
              linkedAt: new Date(),
              lastLoginAt: null,
              avatarUrl: pending.oauth.avatarUrl || null,
            },
          }
        : pending.oauth?.provider === 'github'
          ? {
              github: {
                providerId: pending.oauth.providerId,
                username: pending.oauth.providerUsername || null,
                email: pending.oauth.providerEmail || pending.email,
                emailVerified: !!pending.oauth.providerEmailVerified,
                linkedAt: new Date(),
                lastLoginAt: null,
                avatarUrl: pending.oauth.avatarUrl || null,
                profileUrl: pending.oauth.profileUrl || null,
              },
            }
          : {},
    };

    if (pending.authMode === 'local') {
      userPayload.pin = pending.pinHash;
    }

    userPayload.securityVersion = pending.securityVersion || 1;
    userPayload.userSalt = pending.userSalt || null;
    userPayload.recoverySalt = pending.recoverySalt || null;
    userPayload.wrappedUserKey = pending.wrappedUserKey || null;
    userPayload.wrappedUserKeyRecovery = pending.wrappedUserKeyRecovery || null;

    const user = await User.create(userPayload);

    const session = await createSession(user._id, req, {
      trustDevice: false,
      ...getDeviceContext(req),
    });

    await PendingRegistration.deleteOne({ _id: pending._id });

    return res.status(201).json({
      ...buildAuthResponse(user, session),
      message: 'Account created successfully with MFA enforced.',
    });
  } catch (error) {
    console.error('Complete signup error:', error.message);
    if (error.code === 11000) {
      const field = Object.keys(error.keyPattern || {})[0];
      return res.status(409).json({
        success: false,
        code: 'DUPLICATE_ACCOUNT',
        message: field === 'phone'
          ? 'This phone number is already linked to another account.'
          : 'An account already exists with this email.',
      });
    }
    return res.status(500).json({
      success: false,
      message: 'Unable to complete registration',
    });
  }
};

exports.login = async (req, res) => {
  try {
    if (handleValidationErrors(req, res)) return;

    const { email, pin } = req.body;
    const device = getDeviceContext(req);

    const user = await findUserByEmail(email);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials',
      });
    }

    const isMatch = await user.comparePin(pin);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials',
      });
    }

    if (user.status === 'suspended') {
      return res.status(403).json(SUSPENDED_RESPONSE);
    }

    if (!ensureActiveVerifiedMfaUser(user)) {
      return res.status(403).json({
        success: false,
        message: 'Account setup is incomplete. Finish email verification and MFA enrollment before logging in.',
      });
    }

    const mfaResetRequired = !!user.security.mfa.resetRequired;

    return res.json({
      success: true,
      mfaRequired: true,
      mfaResetRequired,
      challengeToken: signLoginChallenge({
        userId: user._id.toString(),
        deviceId: device.deviceId,
        trustDevice: false,
        deviceName: device.deviceName,
        clientType: device.clientType,
      }),
      methods: mfaResetRequired ? ['email_otp'] : ['totp', 'recovery_code'],
      message: mfaResetRequired
        ? 'Your authenticator was reset. Verify with an email code to continue.'
        : 'Enter your authenticator code to finish signing in.',
    });
  } catch (error) {
    console.error('Login error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Error logging in',
    });
  }
};

exports.verifyLoginMfa = async (req, res) => {
  try {
    if (handleValidationErrors(req, res)) return;

    const { challengeToken, totpCode, recoveryCode, emailOtpCode } = req.body;
    if (!challengeToken) {
      return res.status(400).json({ success: false, message: 'Challenge token is required' });
    }

    const challenge = verifyLoginChallenge(challengeToken);
    const user = await User.findById(challenge.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (user.status === 'suspended') {
      return res.status(403).json(SUSPENDED_RESPONSE);
    }

    // A challenge issued by the admin console only completes for a current admin, and only with
    // the authenticator or a recovery code: the emailed-code shortcut is not available to staff.
    if (challenge.authMethod === 'admin') {
      if (user.role !== 'admin' && user.role !== 'superadmin') {
        return res.status(401).json({ success: false, code: 'ADMIN_LOGIN_FAILED', message: 'Invalid email or password.' });
      }
      if (emailOtpCode) {
        return res.status(403).json({ success: false, code: 'ADMIN_MFA_REQUIRED', message: 'Staff sign in with the authenticator app or a recovery code.' });
      }
    }

    if (!ensureActiveVerifiedMfaUser(user)) {
      return res.status(403).json({ success: false, message: 'Account setup is incomplete.' });
    }

    let verified = false;

    // Email OTP path
    if (emailOtpCode) {
      const challenge2 = await LoginOtpChallenge.findOne({ email: user.email, used: false });
      if (challenge2 && new Date(challenge2.expiresAt).getTime() > Date.now()) {
        if (await compareHashedValue(String(emailOtpCode), challenge2.codeHash)) {
          challenge2.used = true;
          await challenge2.save();
          verified = true;
        }
      }
      if (!verified) {
        return res.status(401).json({ success: false, code: 'EMAIL_OTP_INVALID', message: 'Invalid or expired email OTP.' });
      }
    } else {
      // TOTP / recovery code path
      const verification = await verifyMfaAttempt(user, { totpCode, recoveryCode });
      if (!verification.verified) {
        const failure = mfaFailure(verification.reason);
        return res.status(failure.status).json({ success: false, code: failure.code, message: failure.message });
      }
    }

    const session = await createSession(user._id, req, {
      trustDevice: false,
      deviceId: challenge.deviceId,
      deviceName: challenge.deviceName,
      clientType: challenge.clientType,
    });

    if (challenge.authMethod === 'admin') {
      try {
        await AdminAuditLog.create({
          actorId: user._id,
          actorEmail: user.email,
          action: 'admin.signed_in',
          details: { device: challenge.deviceName || 'Unknown device' },
          ipHash: hashIpAddress(getClientIp(req)),
        });
      } catch (auditError) {
        console.error('AUDIT WRITE FAILED for admin.signed_in:', auditError.message);
      }
    }

    return res.json({ ...buildAuthResponse(user, session), message: 'Login successful' });
  } catch (error) {
    console.error('Login MFA verification error:', error.message);
    if (error.code === 'LOGIN_CHALLENGE_EXPIRED') {
      return res.status(400).json({ success: false, code: 'LOGIN_CHALLENGE_EXPIRED', message: 'Login challenge expired. Start sign-in again.' });
    }
    if (error.code === 'LOGIN_CHALLENGE_INVALID') {
      return res.status(400).json({ success: false, code: 'LOGIN_CHALLENGE_INVALID', message: 'Login challenge is invalid. Start sign-in again.' });
    }
    return res.status(error.status || 500).json({ success: false, message: 'Unable to verify MFA right now' });
  }
};

exports.getProfile = async (req, res) => {
  return res.json({
    success: true,
    user: buildMaskedUser(req.user, req.authSession),
  });
};

exports.getFullProfile = async (req, res) => {
  return res.json({
    success: true,
    user: buildFullUser(req.user, req.authSession),
  });
};

exports.updateProfile = async (req, res) => {
  try {
    const { name, phone, extractedData } = req.body;
    const user = await User.findById(req.userId);

    if (extractedData && !req.stepUpVerified) {
      return res.status(403).json({
        success: false,
        code: 'STEP_UP_REQUIRED',
        message: 'Recent re-authentication is required before changing sensitive extracted data.',
      });
    }

    if (name) user.name = name;
    if (phone !== undefined) user.phone = phone || undefined;

    if (extractedData) {
      user.extractedData = {
        ...(user.extractedData || {}),
        ...extractedData,
      };
    }

    await user.save();

    return res.json({
      success: true,
      message: 'Profile updated successfully',
      user: buildMaskedUser(user, req.authSession),
    });
  } catch (error) {
    console.error('Update profile error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Error updating profile',
    });
  }
};

exports.stepUp = async (req, res) => {
  try {
    const { method, pin, totpCode, recoveryCode } = req.body;

    if (!method || !['pin', 'password', 'totp', 'recovery_code'].includes(method)) {
      return res.status(400).json({
        success: false,
        message: 'A valid step-up method is required',
      });
    }

    let verified = false;
    let stepUpReason = 'INVALID';

    if (method === 'pin') {
      verified = await req.user.comparePin(pin || '');
    } else if (method === 'password') {
      // Staff re-authenticate with the console password. Anyone without one simply fails.
      verified = await compareAdminPassword(req.body.password, req.user.adminPasswordHash);
    } else {
      const verification = await verifyMfaAttempt(req.user, { totpCode, recoveryCode });
      verified = verification.verified;
      stepUpReason = verification.reason;
    }

    if (!verified) {
      const knowledge = method === 'pin' || method === 'password';
      const failure = knowledge ? MFA_FAILURES.INVALID : mfaFailure(stepUpReason);
      return res.status(failure.status).json({
        success: false,
        code: knowledge ? 'STEP_UP_FAILED' : failure.code,
        message: knowledge ? 'Re-authentication failed' : failure.message,
      });
    }

    await markStepUpVerified(req.authSession);

    return res.json({
      success: true,
      message: 'Step-up authentication successful',
      stepUpExpiresAt: req.authSession.stepUpExpiresAt,
    });
  } catch (error) {
    console.error('Step-up error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Error verifying sensitive action access',
    });
  }
};

exports.regenerateRecoveryCodes = async (req, res) => {
  try {
    if (!req.user.security?.mfa?.enabled) {
      return res.status(400).json({
        success: false,
        message: 'MFA must be enabled to regenerate recovery codes',
      });
    }

    const recoveryCodes = await createRecoveryCodes();
    req.user.security.mfa.backupCodeHashes = recoveryCodes.hashedCodes;
    req.user.security.mfa.recoveryCodesGeneratedAt = new Date();
    await req.user.save();

    return res.json({
      success: true,
      message: 'Recovery codes regenerated successfully',
      recoveryCodes: recoveryCodes.plainCodes,
    });
  } catch (error) {
    console.error('Regenerate recovery codes error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Error regenerating recovery codes',
    });
  }
};

exports.updateEmail = async (req, res) => {
  try {
    if (handleValidationErrors(req, res)) return;

    const normalizedEmail = canonicalEmail(req.body.email);

    const existingUser = await User.findOne({
      email: { $in: emailCandidates(normalizedEmail) },
      _id: { $ne: req.userId },
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'Another account is already using this email',
      });
    }

    req.user.email = normalizedEmail;
    req.user.emailVerifiedAt = new Date();
    await req.user.save();

    return res.json({
      success: true,
      message: 'Email updated successfully',
      user: buildMaskedUser(req.user, req.authSession),
    });
  } catch (error) {
    console.error('Update email error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Error updating email',
    });
  }
};

exports.updatePin = async (req, res) => {
  try {
    if (handleValidationErrors(req, res)) return;

    const { currentPin, newPin } = req.body;

    if (req.user.pin && !(await req.user.comparePin(currentPin || ''))) {
      return res.status(401).json({
        success: false,
        message: 'Current PIN is incorrect',
      });
    }

    req.user.pin = newPin;
    req.user.authMethods = {
      ...(req.user.authMethods || {}),
      localPin: true,
      google: !!(req.user.authMethods?.google ?? req.user.providers?.google?.providerId),
      github: !!(req.user.authMethods?.github ?? req.user.providers?.github?.providerId),
    };
    await req.user.save();

    return res.json({
      success: true,
      message: 'PIN updated successfully',
    });
  } catch (error) {
    console.error('Update PIN error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Error updating PIN',
    });
  }
};

exports.listSessions = async (req, res) => {
  try {
    const sessions = await AuthSession.find({
      userId: req.userId,
      revokedAt: null,
    }).sort({ lastSeenAt: -1 });

    return res.json({
      success: true,
      sessions: sessions.map((session) => formatSessionForClient(session, req.authSession.sessionId)),
    });
  } catch (error) {
    console.error('List sessions error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Error loading sessions',
    });
  }
};

exports.logout = async (req, res) => {
  try {
    await revokeSession(req.authSession, 'logout');

    return res.json({
      success: true,
      message: 'Logged out successfully',
    });
  } catch (error) {
    console.error('Logout error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Error logging out',
    });
  }
};

exports.logoutOtherSessions = async (req, res) => {
  try {
    await revokeOtherSessions(req.userId, req.authSession.sessionId);

    return res.json({
      success: true,
      message: 'Other sessions were logged out',
    });
  } catch (error) {
    console.error('Logout other sessions error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Error logging out other sessions',
    });
  }
};

exports.logoutAllSessions = async (req, res) => {
  try {
    await revokeAllSessions(req.userId);

    return res.json({
      success: true,
      message: 'All sessions were logged out',
    });
  } catch (error) {
    console.error('Logout all sessions error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Error logging out all sessions',
    });
  }
};

exports.revokeSession = async (req, res) => {
  try {
    const session = await AuthSession.findOne({
      userId: req.userId,
      sessionId: req.params.sessionId,
      revokedAt: null,
    });

    if (!session) {
      return res.status(404).json({
        success: false,
        message: 'Session not found',
      });
    }

    await revokeSession(session, 'manual_revoke');

    return res.json({
      success: true,
      message: 'Session revoked successfully',
    });
  } catch (error) {
    console.error('Revoke session error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Error revoking session',
    });
  }
};

// ── Email OTP Login ──────────────────────────────────────────────────────────

// Send email OTP during MFA step (after PIN verified, before session created)
exports.sendMfaEmailOtp = async (req, res) => {
  try {
    if (handleValidationErrors(req, res)) return;

    const challenge = verifyLoginChallenge(req.body.challengeToken);
    const user = await User.findById(challenge.userId);
    if (!user || !user.isVerified) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }
    if (user.status === 'suspended') {
      return res.status(403).json(SUSPENDED_RESPONSE);
    }

    const otp = generateNumericOtp(6);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await LoginOtpChallenge.findOneAndUpdate(
      { email: user.email },
      { email: user.email, codeHash: await hashValue(otp), expiresAt, used: false },
      { upsert: true, new: true }
    );

    await sendVerificationEmail({ email: user.email, name: user.name, code: otp, expiresInMinutes: 10 });

    return res.json({ success: true, message: 'OTP sent to your email.' });
  } catch (error) {
    console.error('Send MFA email OTP error:', error.message);
    if (error.code === 'LOGIN_CHALLENGE_EXPIRED') {
      return res.status(400).json({ success: false, message: 'Session expired. Please login again.' });
    }
    return res.status(500).json({ success: false, message: 'Unable to send OTP.' });
  }
};

exports.requestLoginOtp = async (req, res) => {
  try {
    if (handleValidationErrors(req, res)) return;

    const typedEmail = canonicalEmail(req.body.email);
    const user = await findUserByEmail(typedEmail);

    // Always respond success to avoid email enumeration
    if (!user || !user.isVerified) {
      return res.json({ success: true, message: 'If that email exists, a code was sent.' });
    }

    const email = user.email;
    const otp = generateNumericOtp(6);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 min

    await LoginOtpChallenge.findOneAndUpdate(
      { email },
      { email, codeHash: await hashValue(otp), expiresAt, used: false },
      { upsert: true, new: true }
    );

    await sendVerificationEmail({ email, name: user.name, code: otp, expiresInMinutes: 10 });

    return res.json({ success: true, message: 'If that email exists, a code was sent.' });
  } catch (error) {
    console.error('Request login OTP error:', error.message);
    return res.status(500).json({ success: false, message: 'Unable to send OTP' });
  }
};

exports.verifyLoginOtp = async (req, res) => {
  try {
    if (handleValidationErrors(req, res)) return;

    const { code } = req.body;

    const user = await findUserByEmail(canonicalEmail(req.body.email));
    if (!user) {
      return res.status(400).json({ success: false, message: 'OTP expired or not found. Request a new one.' });
    }

    const challenge = await LoginOtpChallenge.findOne({ email: user.email, used: false });

    if (!challenge || new Date(challenge.expiresAt).getTime() <= Date.now()) {
      return res.status(400).json({ success: false, message: 'OTP expired or not found. Request a new one.' });
    }

    if (!(await compareHashedValue(String(code || ''), challenge.codeHash))) {
      return res.status(400).json({ success: false, message: 'Invalid OTP code.' });
    }

    // Mark used
    challenge.used = true;
    await challenge.save();

    // If MFA is enabled, still require TOTP after OTP
    if (ensureActiveVerifiedMfaUser(user)) {
      return res.json({
        success: true,
        mfaRequired: true,
        challengeToken: signLoginChallenge({
          userId: user._id.toString(),
          ...getDeviceContext(req),
          trustDevice: false,
          authMethod: 'email_otp',
        }),
        methods: ['totp', 'recovery_code'],
        message: 'OTP verified. Enter your authenticator code to finish signing in.',
      });
    }

    const session = await createSession(user._id, req, {
      trustDevice: false,
      ...getDeviceContext(req),
    });

    return res.json({ ...buildAuthResponse(user, session), message: 'Login successful' });
  } catch (error) {
    console.error('Verify login OTP error:', error.message);
    return res.status(500).json({ success: false, message: 'Unable to verify OTP' });
  }
};


// ── Forgot Password ──────────────────────────────────────────────────────────

// Step 1: Validate email and send reset code
exports.forgotPassword = async (req, res) => {
  try {
    if (handleValidationErrors(req, res)) return;

    const typedEmail = canonicalEmail(req.body.email);
    const user = await findUserByEmail(typedEmail);

    // Always respond with success to prevent email enumeration
    if (!user || !user.isVerified) {
      return res.json({
        success: true,
        message: 'If that email exists, a password reset code was sent.',
      });
    }

    // Check if user has local PIN auth enabled
    const hasLocalPin = !!(user.authMethods?.localPin ?? user.pin);
    if (!hasLocalPin) {
      // User only uses OAuth, no PIN to reset
      return res.json({
        success: true,
        message: 'If that email exists, a password reset code was sent.',
      });
    }

    const email = user.email;
    const otp = generateNumericOtp(6);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    await PasswordReset.findOneAndUpdate(
      { email },
      { email, codeHash: await hashValue(otp), expiresAt, used: false },
      { upsert: true, new: true }
    );

    await sendPasswordResetEmail({
      email,
      name: user.name,
      code: otp,
      expiresInMinutes: 15,
    });

    return res.json({
      success: true,
      message: 'If that email exists, a password reset code was sent.',
    });
  } catch (error) {
    console.error('Forgot password error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Unable to process password reset request',
    });
  }
};

// Step 2: Verify reset code
exports.verifyResetCode = async (req, res) => {
  try {
    if (handleValidationErrors(req, res)) return;

    const code = String(req.body.code || '');

    const user = await findUserByEmail(canonicalEmail(req.body.email));
    if (!user || !user.isVerified) {
      return res.status(404).json({
        success: false,
        message: 'Invalid or expired reset code',
      });
    }

    const resetRequest = await PasswordReset.findOne({
      email: user.email,
      used: false,
    });

    if (!resetRequest) {
      return res.status(404).json({
        success: false,
        message: 'Invalid or expired reset code',
      });
    }

    if (new Date(resetRequest.expiresAt).getTime() <= Date.now()) {
      return res.status(400).json({
        success: false,
        message: 'Reset code has expired. Please request a new one.',
      });
    }

    if (!(await compareHashedValue(code, resetRequest.codeHash))) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired reset code',
      });
    }

    // Mark code as verified (not used yet, will be used when PIN is actually reset)
    return res.json({
      success: true,
      message: 'Reset code verified. You can now set a new PIN.',
      verified: true,
      wrappedUserKeyRecovery: user.wrappedUserKeyRecovery || null,
      recoverySalt: user.recoverySalt || null,
    });
  } catch (error) {
    console.error('Verify reset code error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Unable to verify reset code',
    });
  }
};

// Step 3: Reset PIN with verified code
exports.resetPassword = async (req, res) => {
  try {
    if (handleValidationErrors(req, res)) return;

    const code = String(req.body.code || '');
    const newPin = String(req.body.newPin || '');

    if (!newPin || newPin.length !== 6 || !/^\d{6}$/.test(newPin)) {
      return res.status(400).json({
        success: false,
        message: 'PIN must be exactly 6 digits',
      });
    }

    const user = await findUserByEmail(canonicalEmail(req.body.email));
    if (!user || !user.isVerified) {
      return res.status(404).json({
        success: false,
        message: 'Unable to reset password',
      });
    }

    const resetRequest = await PasswordReset.findOne({
      email: user.email,
      used: false,
    });

    if (!resetRequest) {
      return res.status(404).json({
        success: false,
        message: 'Invalid or expired reset code',
      });
    }

    if (new Date(resetRequest.expiresAt).getTime() <= Date.now()) {
      return res.status(400).json({
        success: false,
        message: 'Reset code has expired. Please request a new one.',
      });
    }

    if (!(await compareHashedValue(code, resetRequest.codeHash))) {
      return res.status(400).json({
        success: false,
        message: 'Invalid or expired reset code',
      });
    }

    // Update the PIN
    user.pin = newPin;
    user.authMethods = {
      ...(user.authMethods || {}),
      localPin: true,
      google: !!(user.authMethods?.google ?? user.providers?.google?.providerId),
      github: !!(user.authMethods?.github ?? user.providers?.github?.providerId),
    };
    if (req.body.wrappedUserKey) {
      user.wrappedUserKey = req.body.wrappedUserKey;
    }
    await user.save();

    // Mark reset request as used
    resetRequest.used = true;
    await resetRequest.save();

    // Optionally, revoke all existing sessions for security
    await revokeAllSessions(user._id);

    return res.json({
      success: true,
      message: 'PIN reset successfully. You can now login with your new PIN.',
    });
  } catch (error) {
    console.error('Reset password error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Unable to reset password',
    });
  }
};

// Check if email exists (for frontend validation)
exports.checkEmail = async (req, res) => {
  try {
    if (handleValidationErrors(req, res)) return;

    const user = await findUserByEmail(canonicalEmail(req.body.email));

    return res.json({
      success: true,
      exists: !!(user && user.isVerified),
      hasLocalAuth: !!(user && (user.authMethods?.localPin ?? user.pin)),
      userSalt: user ? user.userSalt || null : null,
      securityVersion: user ? user.securityVersion || 1 : 1
    });
  } catch (error) {
    console.error('Check email error:', error.message);
    return res.status(500).json({
      success: false,
      message: 'Unable to check email',
    });
  }
};

exports.getKeys = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    return res.json({
      success: true,
      wrappedUserKey: user.wrappedUserKey || null,
      wrappedUserKeyRecovery: user.wrappedUserKeyRecovery || null,
      recoverySalt: user.recoverySalt || null,
    });
  } catch (error) {
    console.error('Get keys error:', error.message);
    return res.status(500).json({ success: false, message: 'Unable to retrieve key metadata' });
  }
};

const PENDING_TOTP_TTL_MS = 10 * 60 * 1000;

exports.setupNewTotp = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const secret = generateMfaSecret(user.email);
    const qrCodeDataUrl = await buildQrCodeDataUrl(secret.otpauth_url);
    const encryptedSecret = encryptText(secret.base32);

    // Persisted (encrypted) so the pending setup survives restarts and multiple
    // instances; calling setup again simply replaces it.
    user.security.mfa.pendingSecretEncrypted = encryptedSecret.encrypted;
    user.security.mfa.pendingSecretIv = encryptedSecret.iv;
    user.security.mfa.pendingSecretAuthTag = encryptedSecret.authTag;
    user.security.mfa.pendingSecretCreatedAt = new Date();
    await user.save();

    return res.json({
      success: true,
      secret: secret.base32,
      qrCodeDataUrl,
      message: 'Scan the QR code with your authenticator app and enter the 6-digit code to confirm.',
    });
  } catch (error) {
    console.error('Setup new TOTP error:', error);
    return res.status(500).json({ success: false, message: 'Error setting up new authenticator' });
  }
};

exports.confirmNewTotp = async (req, res) => {
  try {
    if (handleValidationErrors(req, res)) return;

    const user = await User.findById(req.userId);
    const mfa = user?.security?.mfa;
    const createdAt = mfa?.pendingSecretCreatedAt ? new Date(mfa.pendingSecretCreatedAt).getTime() : 0;

    if (!mfa?.pendingSecretEncrypted || Date.now() - createdAt > PENDING_TOTP_TTL_MS) {
      return res.status(400).json({
        success: false,
        code: 'TOTP_SETUP_EXPIRED',
        message: 'Authenticator setup session expired. Please click Setup Authenticator again.',
      });
    }

    const pendingSecret = decryptText({
      encrypted: mfa.pendingSecretEncrypted,
      iv: mfa.pendingSecretIv,
      authTag: mfa.pendingSecretAuthTag,
    });

    const result = verifyTotp(pendingSecret, req.body.totpCode);
    if (!result.valid) {
      return res.status(400).json({
        success: false,
        code: 'MFA_INVALID_CODE',
        message: 'Invalid 6-digit code. Please try again.',
      });
    }

    const { encrypted, iv, authTag } = encryptText(pendingSecret);
    const recovery = await createRecoveryCodes();

    user.security.mfa = {
      enabled: true,
      secretEncrypted: encrypted,
      secretIv: iv,
      secretAuthTag: authTag,
      backupCodeHashes: recovery.hashedCodes,
      enabledAt: new Date(),
      lastVerifiedAt: new Date(),
      lastUsedTotpStep: result.step,
      recoveryCodesGeneratedAt: new Date(),
    };

    await user.save();

    return res.json({
      success: true,
      message: 'Authenticator app updated successfully!',
      recoveryCodes: recovery.plainCodes,
    });
  } catch (error) {
    console.error('Confirm new TOTP error:', error);
    return res.status(500).json({ success: false, message: 'Error confirming new authenticator' });
  }
};

exports.syncVaultData = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const { extractedData, phone } = req.body;
    if (phone && !user.phone) {
      user.phone = phone;
    }

    if (extractedData && typeof extractedData === 'object') {
      user.extractedData = {
        ...(user.extractedData || {}),
        ...extractedData
      };
    }

    await user.save();
    return res.json({
      success: true,
      message: 'Vault data synchronized successfully',
      extractedData: user.extractedData
    });
  } catch (error) {
    console.error('syncVaultData error:', error);
    return res.status(500).json({ success: false, message: 'Failed to sync vault data' });
  }
};


