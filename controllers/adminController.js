const mongoose = require('mongoose');
const User = require('../models/User');
const AuthSession = require('../models/AuthSession');
const Document = require('../models/Document');
const PasswordReset = require('../models/PasswordReset');
const LoginOtpChallenge = require('../models/LoginOtpChallenge');
const PendingRegistration = require('../models/PendingRegistration');
const AdminAuditLog = require('../models/AdminAuditLog');
const whatsapp = require('../services/whatsappService');
const StorageService = require('../services/storageService');
const { sendPasswordResetEmail } = require('../services/emailService');
const { createSession, revokeAllSessions, revokeSession, signLoginChallenge } = require('../services/sessionService');
const { canonicalEmail, findUserByEmail } = require('../services/accountService');
const { validationResult } = require('express-validator');
const { buildAuthResponse } = require('./authController');
const {
  compareAdminPassword,
  generateNumericOtp,
  getClientIp,
  getDeviceContext,
  hashIpAddress,
  hashValue,
  maskValueByField,
} = require('../services/securityService');

const ROLES = ['user', 'admin', 'superadmin'];
const MAX_PAGE_SIZE = 100;

const fail = (res, status, code, message) => res.status(status).json({ success: false, code, message });

const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const toInt = (value, fallback, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) => {
  const parsed = parseInt(value, 10);
  if (Number.isNaN(parsed)) return fallback;
  return Math.min(Math.max(parsed, min), max);
};

// Best effort: an audit write failure is logged loudly but never undoes the action.
const audit = async (req, action, target = null, details = {}) => {
  try {
    await AdminAuditLog.create({
      actorId: req.userId,
      actorEmail: req.user.email,
      action,
      targetUserId: target?._id || null,
      targetEmail: target?.email || null,
      details,
      ipHash: hashIpAddress(getClientIp(req)),
    });
  } catch (error) {
    console.error(`AUDIT WRITE FAILED for ${action}:`, error.message);
  }
};

// Whether the console asks for the authenticator code after the password. Read on every request so
// it can be switched with an environment variable and a restart. Off means password only.
const requireMfa = () => process.env.ADMIN_REQUIRE_MFA === 'true';

exports.getConfig = (req, res) => res.json({ success: true, config: { requireMfa: requireMfa() } });

// ── Sign-in (the only admin route that needs no session) ─────────────────────
const STAFF_ROLES = new Set(['admin', 'superadmin']);
const MAX_FAILED_LOGINS = 5;
const LOCKOUT_MINUTES = 15;
const LOGIN_FAILED = { status: 401, code: 'ADMIN_LOGIN_FAILED', message: 'Invalid email or password.' };

// Step one of two: email and the dedicated admin password. It only returns a short-lived
// challenge; the session is issued after the authenticator code (POST /auth/login/verify-mfa).
// Every reason to refuse looks the same from outside, so the form cannot be used to find out
// who is staff.
exports.login = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return fail(res, LOGIN_FAILED.status, LOGIN_FAILED.code, LOGIN_FAILED.message);

    const user = await findUserByEmail(canonicalEmail(req.body.email));
    const staff = !!user && STAFF_ROLES.has(user.role) && !!user.adminPasswordHash;
    const locked = !!user && user.adminLockedUntil && new Date(user.adminLockedUntil).getTime() > Date.now();

    // One bcrypt comparison on every path, so timing does not separate the cases.
    const matched = await compareAdminPassword(req.body.password, staff && !locked ? user.adminPasswordHash : null);

    if (!staff || locked || !matched) {
      if (staff && !locked) {
        const failures = (user.adminFailedLogins || 0) + 1;
        const lock = failures >= MAX_FAILED_LOGINS;
        await User.updateOne(
          { _id: user._id },
          { $set: { adminFailedLogins: lock ? 0 : failures, adminLockedUntil: lock ? new Date(Date.now() + LOCKOUT_MINUTES * 60000) : null } }
        );
      }
      return fail(res, LOGIN_FAILED.status, LOGIN_FAILED.code, LOGIN_FAILED.message);
    }

    if (user.adminFailedLogins || user.adminLockedUntil) {
      await User.updateOne({ _id: user._id }, { $set: { adminFailedLogins: 0, adminLockedUntil: null } });
    }

    if (user.status === 'suspended') {
      return fail(res, 403, 'ACCOUNT_SUSPENDED', 'This account has been suspended. Contact a super admin.');
    }
    const mfa = user.security?.mfa;
    if (!user.isVerified || !user.emailVerifiedAt || !mfa?.enabled) {
      return fail(res, 403, 'ADMIN_SETUP_INCOMPLETE', 'Finish setting up this account in the FormOS app (verified email), then come back.');
    }

    const device = getDeviceContext(req);

    // Password only: the session is issued right here.
    if (!requireMfa()) {
      const session = await createSession(user._id, req, { trustDevice: false, ...device });
      req.userId = user._id;
      req.user = user;
      await audit(req, 'admin.signed_in', null, { device: device.deviceName || 'Unknown device' });
      return res.json({ ...buildAuthResponse(user, session), mfaRequired: false, message: 'Signed in' });
    }

    if (!mfa.secretEncrypted) {
      return fail(res, 403, 'ADMIN_SETUP_INCOMPLETE', 'Finish setting up this account in the FormOS app (verified email and authenticator), then come back.');
    }
    if (mfa.resetRequired) {
      return fail(res, 403, 'ADMIN_MFA_RESET', 'Your authenticator was reset. Sign in to the FormOS app with an emailed code and set up a new one, then come back.');
    }

    return res.json({
      success: true,
      mfaRequired: true,
      challengeToken: signLoginChallenge({
        userId: user._id.toString(),
        deviceId: device.deviceId,
        trustDevice: false,
        deviceName: device.deviceName,
        clientType: device.clientType,
        authMethod: 'admin',
      }),
      methods: ['totp', 'recovery_code'],
      message: 'Password accepted. Enter the code from your authenticator app.',
    });
  } catch (error) {
    console.error('Admin login error:', error.message);
    return fail(res, 500, 'ADMIN_ERROR', 'Unable to sign in right now.');
  }
};

// ── Permission rules ─────────────────────────────────────────────────────────
// admin      → can manage regular users only
// superadmin → can also manage admins, change roles and delete accounts
// nobody     → can suspend / delete / re-role themselves, or remove the last superadmin
const loadTarget = async (req, res, { allowSelf = false, viewOnly = false } = {}) => {
  if (!mongoose.isValidObjectId(req.params.id)) {
    fail(res, 400, 'INVALID_ID', 'Invalid user id.');
    return null;
  }

  const target = await User.findById(req.params.id);
  if (!target) {
    fail(res, 404, 'USER_NOT_FOUND', 'User not found.');
    return null;
  }

  if (!allowSelf && String(target._id) === String(req.userId)) {
    fail(res, 400, 'SELF_ACTION', 'You cannot perform this action on your own account.');
    return null;
  }

  const actorIsSuper = req.user.role === 'superadmin';
  if (!viewOnly && !actorIsSuper && (target.role || 'user') !== 'user') {
    fail(res, 403, 'INSUFFICIENT_ROLE', 'Only a super administrator can manage administrator accounts.');
    return null;
  }

  return target;
};

const isLastSuperadmin = async (target) => {
  if (target.role !== 'superadmin') return false;
  const count = await User.countDocuments({ role: 'superadmin', status: { $ne: 'suspended' } });
  return count <= 1;
};

// ── Serializers (metadata only: no document contents, no extracted PII, no secrets) ──
const summarizeUser = (user, extras = {}) => ({
  id: user._id,
  name: user.name,
  email: user.email,
  phone: user.phone ? maskValueByField('phone', user.phone) : '',
  role: user.role || 'user',
  status: user.status || 'active',
  isVerified: !!user.isVerified,
  mfaEnabled: !!user.security?.mfa?.enabled,
  mfaResetRequired: !!user.security?.mfa?.resetRequired,
  authMethods: {
    pin: !!(user.authMethods?.localPin ?? user.pin),
    google: !!user.providers?.google?.providerId,
    github: !!user.providers?.github?.providerId,
  },
  securityVersion: user.securityVersion || 1,
  createdAt: user.createdAt,
  suspendedAt: user.status === 'suspended' ? user.suspendedAt : null,
  suspendedReason: user.status === 'suspended' ? user.suspendedReason : null,
  mfaResetRequestedAt: user.security?.mfa?.resetRequired ? user.security?.mfa?.resetRequestedAt || null : null,
  documentCount: 0,
  activeSessions: 0,
  lastSeenAt: null,
  ...extras,
});

const enrichUsers = async (users) => {
  const ids = users.map((user) => user._id);
  const [docs, sessions] = await Promise.all([
    Document.aggregate([
      { $match: { userId: { $in: ids } } },
      { $group: { _id: '$userId', count: { $sum: 1 } } },
    ]),
    AuthSession.aggregate([
      { $match: { userId: { $in: ids } } },
      {
        $group: {
          _id: '$userId',
          active: { $sum: { $cond: [{ $eq: ['$revokedAt', null] }, 1, 0] } },
          lastSeenAt: { $max: '$lastSeenAt' },
        },
      },
    ]),
  ]);

  const docMap = new Map(docs.map((entry) => [String(entry._id), entry.count]));
  const sessionMap = new Map(sessions.map((entry) => [String(entry._id), entry]));

  return users.map((user) => {
    const session = sessionMap.get(String(user._id));
    return summarizeUser(user, {
      documentCount: docMap.get(String(user._id)) || 0,
      activeSessions: session?.active || 0,
      lastSeenAt: session?.lastSeenAt || null,
    });
  });
};

// ── Overview ─────────────────────────────────────────────────────────────────
exports.getStats = async (req, res) => {
  try {
    const now = Date.now();
    const day = 24 * 60 * 60 * 1000;
    const since7 = new Date(now - 7 * day);
    const since30 = new Date(now - 30 * day);
    const since24h = new Date(now - day);

    const [
      totalUsers, verifiedUsers, suspendedUsers, adminUsers, mfaResetPending, new7, new30,
      signupsByDay, pinUsers, googleUsers, githubUsers, v2Users,
      activeSessions, activeUserIds,
      docTotals, docsByType, docsByStatus, docs7,
      pendingRegistrations, recentActivity,
    ] = await Promise.all([
      User.countDocuments({}),
      User.countDocuments({ isVerified: true }),
      User.countDocuments({ status: 'suspended' }),
      User.countDocuments({ role: { $in: ['admin', 'superadmin'] } }),
      User.countDocuments({ 'security.mfa.resetRequired': true }),
      User.countDocuments({ createdAt: { $gte: since7 } }),
      User.countDocuments({ createdAt: { $gte: since30 } }),
      User.aggregate([
        { $match: { createdAt: { $gte: since30 } } },
        { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, count: { $sum: 1 } } },
      ]),
      User.countDocuments({ $or: [{ 'authMethods.localPin': true }, { pin: { $nin: [null, ''] } }] }),
      User.countDocuments({ 'providers.google.providerId': { $exists: true, $nin: [null, ''] } }),
      User.countDocuments({ 'providers.github.providerId': { $exists: true, $nin: [null, ''] } }),
      User.countDocuments({ securityVersion: 2 }),
      AuthSession.countDocuments({ revokedAt: null }),
      AuthSession.distinct('userId', { revokedAt: null, lastSeenAt: { $gte: since24h } }),
      Document.aggregate([{ $group: { _id: null, count: { $sum: 1 }, bytes: { $sum: '$fileSize' } } }]),
      Document.aggregate([{ $group: { _id: '$documentType', count: { $sum: 1 } } }]),
      Document.aggregate([{ $group: { _id: '$ocrStatus', count: { $sum: 1 } } }]),
      Document.countDocuments({ uploadedAt: { $gte: since7 } }),
      PendingRegistration.countDocuments({}),
      AdminAuditLog.find({}).sort({ createdAt: -1 }).limit(8).lean(),
    ]);

    const byDay = new Map(signupsByDay.map((entry) => [entry._id, entry.count]));
    const signups = [];
    for (let i = 29; i >= 0; i -= 1) {
      const date = new Date(now - i * day).toISOString().slice(0, 10);
      signups.push({ date, count: byDay.get(date) || 0 });
    }

    const toMap = (rows) => Object.fromEntries(rows.map((row) => [row._id || 'unknown', row.count]));

    return res.json({
      success: true,
      stats: {
        users: {
          total: totalUsers,
          verified: verifiedUsers,
          unverified: totalUsers - verifiedUsers,
          suspended: suspendedUsers,
          admins: adminUsers,
          mfaResetPending,
          new7d: new7,
          new30d: new30,
          activeLast24h: activeUserIds.length,
          securityV2: v2Users,
        },
        authMethods: { pin: pinUsers, google: googleUsers, github: githubUsers },
        sessions: { active: activeSessions },
        documents: {
          total: docTotals[0]?.count || 0,
          totalBytes: docTotals[0]?.bytes || 0,
          uploaded7d: docs7,
          byType: toMap(docsByType),
          byStatus: toMap(docsByStatus),
        },
        pendingRegistrations,
        signups,
        recentActivity: recentActivity.map((entry) => ({
          id: entry._id,
          action: entry.action,
          actorEmail: entry.actorEmail,
          targetEmail: entry.targetEmail,
          createdAt: entry.createdAt,
        })),
      },
    });
  } catch (error) {
    console.error('Admin stats error:', error.message);
    return fail(res, 500, 'ADMIN_ERROR', 'Unable to load statistics.');
  }
};

// ── Users ────────────────────────────────────────────────────────────────────
exports.listUsers = async (req, res) => {
  try {
    const { search, status, role, verified, provider, mfaReset } = req.query;
    const page = toInt(req.query.page, 1);
    const limit = toInt(req.query.limit, 20, { max: MAX_PAGE_SIZE });
    const filter = {};

    if (typeof search === 'string' && search.trim()) {
      const pattern = new RegExp(escapeRegex(search.trim().slice(0, 100)), 'i');
      filter.$or = [{ name: pattern }, { email: pattern }, { phone: pattern }];
    }
    if (['active', 'suspended'].includes(status)) filter.status = status;
    if (role === 'staff') filter.role = { $in: ['admin', 'superadmin'] };
    else if (ROLES.includes(role)) filter.role = role;
    if (verified === 'true') filter.isVerified = true;
    if (verified === 'false') filter.isVerified = false;
    if (mfaReset === 'true') filter['security.mfa.resetRequired'] = true;
    if (provider === 'google') filter['providers.google.providerId'] = { $exists: true, $nin: [null, ''] };
    if (provider === 'github') filter['providers.github.providerId'] = { $exists: true, $nin: [null, ''] };
    if (provider === 'pin') filter.$and = [...(filter.$and || []), { $or: [{ 'authMethods.localPin': true }, { pin: { $nin: [null, ''] } }] }];

    const sortField = ['createdAt', 'name', 'email'].includes(req.query.sort) ? req.query.sort : 'createdAt';
    const sortOrder = req.query.order === 'asc' ? 1 : -1;

    const [total, users] = await Promise.all([
      User.countDocuments(filter),
      User.find(filter)
        .sort({ [sortField]: sortOrder, _id: 1 })
        .skip((page - 1) * limit)
        .limit(limit),
    ]);

    return res.json({
      success: true,
      users: await enrichUsers(users),
      pagination: { page, limit, total, pages: Math.max(1, Math.ceil(total / limit)) },
    });
  } catch (error) {
    console.error('Admin list users error:', error.message);
    return fail(res, 500, 'ADMIN_ERROR', 'Unable to load users.');
  }
};

exports.getUser = async (req, res) => {
  try {
    // Viewing is allowed for any admin; only mutations are role-restricted.
    const target = await loadTarget(req, res, { allowSelf: true, viewOnly: true });
    if (!target) return undefined;

    const [documents, sessions, auditEntries, suspendedBy] = await Promise.all([
      Document.find({ userId: target._id })
        .sort({ uploadedAt: -1 })
        .limit(100)
        .select('originalName documentType fileSize mimeType ocrStatus securityVersion storageType uploadedAt')
        .lean(),
      AuthSession.find({ userId: target._id, revokedAt: null }).sort({ lastSeenAt: -1 }).limit(50).lean(),
      AdminAuditLog.find({ targetUserId: target._id }).sort({ createdAt: -1 }).limit(25).lean(),
      target.suspendedBy ? User.findById(target.suspendedBy).select('email').lean() : null,
    ]);

    const summary = (await enrichUsers([target]))[0];

    return res.json({
      success: true,
      user: {
        ...summary,
        emailVerifiedAt: target.emailVerifiedAt || null,
        updatedAt: target.updatedAt,
        mfa: {
          enabled: !!target.security?.mfa?.enabled,
          enabledAt: target.security?.mfa?.enabledAt || null,
          lastVerifiedAt: target.security?.mfa?.lastVerifiedAt || null,
          recoveryCodesRemaining: target.security?.mfa?.backupCodeHashes?.length || 0,
          resetRequired: !!target.security?.mfa?.resetRequired,
          resetRequestedAt: target.security?.mfa?.resetRequestedAt || null,
        },
        providers: {
          google: {
            linked: !!target.providers?.google?.providerId,
            email: target.providers?.google?.email || '',
            linkedAt: target.providers?.google?.linkedAt || null,
          },
          github: {
            linked: !!target.providers?.github?.providerId,
            username: target.providers?.github?.username || '',
            linkedAt: target.providers?.github?.linkedAt || null,
          },
        },
        suspension: target.status === 'suspended'
          ? {
              at: target.suspendedAt,
              reason: target.suspendedReason,
              by: suspendedBy?.email || null,
            }
          : null,
      },
      sessions: sessions.map((session) => ({
        id: session.sessionId,
        deviceName: session.deviceName,
        clientType: session.clientType,
        userAgent: (session.userAgent || '').slice(0, 160),
        createdAt: session.createdAt,
        lastSeenAt: session.lastSeenAt,
        trustedUntil: session.trustedUntil,
      })),
      documents: documents.map((doc) => ({
        id: doc._id,
        name: doc.originalName,
        type: doc.documentType,
        size: doc.fileSize,
        mimeType: doc.mimeType,
        ocrStatus: doc.ocrStatus,
        securityVersion: doc.securityVersion || 1,
        storageType: doc.storageType,
        uploadedAt: doc.uploadedAt,
      })),
      audit: auditEntries.map((entry) => ({
        id: entry._id,
        action: entry.action,
        actorEmail: entry.actorEmail,
        details: entry.details,
        createdAt: entry.createdAt,
      })),
      permissions: {
        canManage: req.user.role === 'superadmin' || (target.role || 'user') === 'user',
        isSelf: String(target._id) === String(req.userId),
        canChangeRole: req.user.role === 'superadmin' && String(target._id) !== String(req.userId),
        canDelete: req.user.role === 'superadmin' && String(target._id) !== String(req.userId),
      },
    });
  } catch (error) {
    console.error('Admin get user error:', error.message);
    return fail(res, 500, 'ADMIN_ERROR', 'Unable to load user.');
  }
};

// ── Account actions ──────────────────────────────────────────────────────────
exports.suspendUser = async (req, res) => {
  try {
    const target = await loadTarget(req, res);
    if (!target) return undefined;

    const reason = String(req.body.reason || '').trim();
    if (reason.length < 3 || reason.length > 300) {
      return fail(res, 400, 'REASON_REQUIRED', 'Provide a reason (3 to 300 characters) for the suspension.');
    }
    if (target.status === 'suspended') {
      return fail(res, 400, 'ALREADY_SUSPENDED', 'This account is already suspended.');
    }
    if (await isLastSuperadmin(target)) {
      return fail(res, 400, 'LAST_SUPERADMIN', 'The last active super administrator cannot be suspended.');
    }

    target.status = 'suspended';
    target.suspendedAt = new Date();
    target.suspendedReason = reason;
    target.suspendedBy = req.userId;
    await target.save();
    const revoked = await revokeAllSessions(target._id);

    await audit(req, 'user.suspend', target, { reason, sessionsRevoked: revoked.modifiedCount });
    return res.json({ success: true, message: 'Account suspended and all sessions revoked.' });
  } catch (error) {
    console.error('Admin suspend error:', error.message);
    return fail(res, 500, 'ADMIN_ERROR', 'Unable to suspend this account.');
  }
};

exports.unsuspendUser = async (req, res) => {
  try {
    const target = await loadTarget(req, res);
    if (!target) return undefined;
    if (target.status !== 'suspended') {
      return fail(res, 400, 'NOT_SUSPENDED', 'This account is not suspended.');
    }

    target.status = 'active';
    target.suspendedAt = null;
    target.suspendedReason = null;
    target.suspendedBy = null;
    await target.save();

    await audit(req, 'user.unsuspend', target);
    return res.json({ success: true, message: 'Account reactivated.' });
  } catch (error) {
    console.error('Admin unsuspend error:', error.message);
    return fail(res, 500, 'ADMIN_ERROR', 'Unable to reactivate this account.');
  }
};

exports.revokeUserSessions = async (req, res) => {
  try {
    const target = await loadTarget(req, res, { allowSelf: false });
    if (!target) return undefined;

    const result = await revokeAllSessions(target._id);
    await audit(req, 'user.sessions_revoked', target, { count: result.modifiedCount });
    return res.json({ success: true, message: `Signed out ${result.modifiedCount} session(s).`, revoked: result.modifiedCount });
  } catch (error) {
    console.error('Admin revoke sessions error:', error.message);
    return fail(res, 500, 'ADMIN_ERROR', 'Unable to revoke sessions.');
  }
};

exports.revokeUserSession = async (req, res) => {
  try {
    const target = await loadTarget(req, res);
    if (!target) return undefined;

    const session = await AuthSession.findOne({ userId: target._id, sessionId: req.params.sessionId, revokedAt: null });
    if (!session) return fail(res, 404, 'SESSION_NOT_FOUND', 'Session not found.');

    await revokeSession(session, 'admin_revoke');
    await audit(req, 'user.session_revoked', target, { device: session.deviceName });
    return res.json({ success: true, message: 'Session revoked.' });
  } catch (error) {
    console.error('Admin revoke session error:', error.message);
    return fail(res, 500, 'ADMIN_ERROR', 'Unable to revoke the session.');
  }
};

exports.resetUserMfa = async (req, res) => {
  try {
    const target = await loadTarget(req, res);
    if (!target) return undefined;
    if (!target.security?.mfa?.enabled) {
      return fail(res, 400, 'MFA_NOT_ENROLLED', 'This user has not completed authenticator enrollment.');
    }

    target.security.mfa.resetRequired = true;
    target.security.mfa.resetRequestedAt = new Date();
    await target.save();
    const revoked = await revokeAllSessions(target._id);

    await audit(req, 'user.mfa_reset', target, { sessionsRevoked: revoked.modifiedCount });
    return res.json({
      success: true,
      message: 'Authenticator reset. The user must verify with an email code and enroll a new authenticator at next sign-in.',
    });
  } catch (error) {
    console.error('Admin MFA reset error:', error.message);
    return fail(res, 500, 'ADMIN_ERROR', 'Unable to reset the authenticator.');
  }
};

exports.cancelUserMfaReset = async (req, res) => {
  try {
    const target = await loadTarget(req, res);
    if (!target) return undefined;
    if (!target.security?.mfa?.resetRequired) {
      return fail(res, 400, 'NO_MFA_RESET', 'No authenticator reset is pending for this user.');
    }

    target.security.mfa.resetRequired = false;
    target.security.mfa.resetRequestedAt = undefined;
    await target.save();

    await audit(req, 'user.mfa_reset_cancelled', target);
    return res.json({ success: true, message: 'Authenticator reset cancelled.' });
  } catch (error) {
    console.error('Admin cancel MFA reset error:', error.message);
    return fail(res, 500, 'ADMIN_ERROR', 'Unable to cancel the reset.');
  }
};

exports.sendPinReset = async (req, res) => {
  try {
    const target = await loadTarget(req, res);
    if (!target) return undefined;
    if (!(target.authMethods?.localPin ?? target.pin)) {
      return fail(res, 400, 'NO_PIN', 'This account signs in with a provider and has no PIN to reset.');
    }

    const code = generateNumericOtp(6);
    await PasswordReset.findOneAndUpdate(
      { email: target.email },
      { email: target.email, codeHash: await hashValue(code), expiresAt: new Date(Date.now() + 15 * 60 * 1000), used: false },
      { upsert: true, new: true }
    );
    await sendPasswordResetEmail({ email: target.email, name: target.name, code, expiresInMinutes: 15 });

    await audit(req, 'user.pin_reset_sent', target);
    return res.json({ success: true, message: 'A PIN reset code was emailed to the user.' });
  } catch (error) {
    console.error('Admin PIN reset error:', error.message);
    return fail(res, 500, 'ADMIN_ERROR', 'Unable to send the PIN reset email.');
  }
};

exports.changeRole = async (req, res) => {
  try {
    const target = await loadTarget(req, res);
    if (!target) return undefined;

    const role = String(req.body.role || '');
    if (!ROLES.includes(role)) return fail(res, 400, 'INVALID_ROLE', 'Role must be user, admin or superadmin.');
    if (role === target.role) return fail(res, 400, 'NO_CHANGE', 'The user already has this role.');
    if (role !== 'superadmin' && (await isLastSuperadmin(target))) {
      return fail(res, 400, 'LAST_SUPERADMIN', 'The last active super administrator cannot be demoted.');
    }
    if (role !== 'user' && target.status === 'suspended') {
      return fail(res, 400, 'SUSPENDED_TARGET', 'Reactivate this account before giving it administrator access.');
    }

    const previous = target.role || 'user';
    target.role = role;
    await target.save();

    await audit(req, 'user.role_changed', target, { from: previous, to: role });
    return res.json({ success: true, message: `Role changed from ${previous} to ${role}.` });
  } catch (error) {
    console.error('Admin change role error:', error.message);
    return fail(res, 500, 'ADMIN_ERROR', 'Unable to change the role.');
  }
};

exports.deleteUser = async (req, res) => {
  try {
    const target = await loadTarget(req, res);
    if (!target) return undefined;

    if (String(req.body.confirmEmail || '').trim().toLowerCase() !== target.email.toLowerCase()) {
      return fail(res, 400, 'CONFIRMATION_MISMATCH', 'Type the account email exactly to confirm deletion.');
    }
    if (await isLastSuperadmin(target)) {
      return fail(res, 400, 'LAST_SUPERADMIN', 'The last active super administrator cannot be deleted.');
    }

    const documents = await Document.find({ userId: target._id });
    let filesRemoved = 0;
    let fileErrors = 0;
    for (const document of documents) {
      try {
        await StorageService.deleteFile(document);
        filesRemoved += 1;
      } catch (error) {
        if (error.code === 'ENOENT') {
          filesRemoved += 1; // already gone, which is the outcome we wanted
        } else {
          fileErrors += 1;
          console.error(`Admin delete: stored file for document ${document._id} could not be removed:`, error.message);
        }
      }
    }

    await Document.deleteMany({ userId: target._id });
    await AuthSession.deleteMany({ userId: target._id });
    await Promise.all([
      PasswordReset.deleteMany({ email: target.email }),
      LoginOtpChallenge.deleteMany({ email: target.email }),
      PendingRegistration.deleteMany({ email: target.email }),
    ]);
    await User.deleteOne({ _id: target._id });

    await audit(req, 'user.deleted', target, { documentsDeleted: documents.length, filesRemoved, fileErrors });
    return res.json({
      success: true,
      message: `Account deleted along with ${documents.length} document(s).`,
      fileErrors,
    });
  } catch (error) {
    console.error('Admin delete user error:', error.message);
    return fail(res, 500, 'ADMIN_ERROR', 'Unable to delete this account.');
  }
};

exports.deleteUserDocument = async (req, res) => {
  try {
    const target = await loadTarget(req, res);
    if (!target) return undefined;
    if (!mongoose.isValidObjectId(req.params.docId)) return fail(res, 400, 'INVALID_ID', 'Invalid document id.');

    const document = await Document.findOne({ _id: req.params.docId, userId: target._id });
    if (!document) return fail(res, 404, 'DOCUMENT_NOT_FOUND', 'Document not found.');

    try {
      await StorageService.deleteFile(document);
    } catch (error) {
      if (error.code !== 'ENOENT') {
        console.error('Admin delete document: stored file could not be removed:', error.message);
      }
    }
    await document.deleteOne();

    await audit(req, 'document.deleted', target, { name: document.originalName, type: document.documentType });
    return res.json({ success: true, message: 'Document deleted.' });
  } catch (error) {
    console.error('Admin delete document error:', error.message);
    return fail(res, 500, 'ADMIN_ERROR', 'Unable to delete the document.');
  }
};

// ── Audit log + pending registrations ────────────────────────────────────────
exports.listAudit = async (req, res) => {
  try {
    const page = toInt(req.query.page, 1);
    const limit = toInt(req.query.limit, 25, { max: MAX_PAGE_SIZE });
    const filter = {};

    if (typeof req.query.action === 'string' && /^[a-z_.]{1,60}$/.test(req.query.action)) {
      filter.action = req.query.action;
    }
    if (typeof req.query.q === 'string' && req.query.q.trim()) {
      const pattern = new RegExp(escapeRegex(req.query.q.trim().slice(0, 100)), 'i');
      filter.$or = [{ actorEmail: pattern }, { targetEmail: pattern }];
    }

    const [total, entries] = await Promise.all([
      AdminAuditLog.countDocuments(filter),
      AdminAuditLog.find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean(),
    ]);

    return res.json({
      success: true,
      entries: entries.map((entry) => ({
        id: entry._id,
        action: entry.action,
        actorEmail: entry.actorEmail,
        targetUserId: entry.targetUserId,
        targetEmail: entry.targetEmail,
        details: entry.details,
        createdAt: entry.createdAt,
      })),
      pagination: { page, limit, total, pages: Math.max(1, Math.ceil(total / limit)) },
    });
  } catch (error) {
    console.error('Admin audit list error:', error.message);
    return fail(res, 500, 'ADMIN_ERROR', 'Unable to load the audit log.');
  }
};

exports.listPendingRegistrations = async (req, res) => {
  try {
    const pending = await PendingRegistration.find({}).sort({ createdAt: -1 }).limit(100).lean();
    return res.json({
      success: true,
      registrations: pending.map((entry) => ({
        id: entry._id,
        name: entry.name,
        email: entry.email,
        method: entry.authMode === 'oauth' ? entry.oauth?.provider || 'oauth' : 'email',
        emailVerified: !!entry.emailVerifiedAt,
        authenticatorVerified: !!entry.security?.mfa?.verifiedAt,
        createdAt: entry.createdAt,
        expiresAt: entry.expiresAt,
      })),
    });
  } catch (error) {
    console.error('Admin pending list error:', error.message);
    return fail(res, 500, 'ADMIN_ERROR', 'Unable to load pending registrations.');
  }
};

exports.deletePendingRegistration = async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return fail(res, 400, 'INVALID_ID', 'Invalid id.');
    const pending = await PendingRegistration.findByIdAndDelete(req.params.id);
    if (!pending) return fail(res, 404, 'NOT_FOUND', 'Registration not found.');

    await audit(req, 'registration.deleted', { email: pending.email });
    return res.json({ success: true, message: 'Pending registration removed.' });
  } catch (error) {
    console.error('Admin delete pending error:', error.message);
    return fail(res, 500, 'ADMIN_ERROR', 'Unable to remove the registration.');
  }
};

// ---- WhatsApp assistant account -------------------------------------------------------------
// One WhatsApp account sends and receives for every member. Admins link it by scanning the QR code
// here. Only the account's own state is shown: never any member's messages.

const whatsappView = async () => ({
  ...whatsapp.getStatus(),
  linkedMembers: await User.countDocuments({ 'whatsapp.number': { $type: 'string' } }),
});

exports.getWhatsApp = async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store');
    res.json({ success: true, whatsapp: await whatsappView() });
  } catch (error) {
    console.error('Admin WhatsApp status error:', error);
    res.status(500).json({ success: false, message: 'Could not load the WhatsApp status.' });
  }
};

exports.connectWhatsApp = async (req, res) => {
  try {
    await whatsapp.start();
    await audit(req, 'whatsapp.connect', null, { state: whatsapp.getStatus().state });
    res.json({ success: true, whatsapp: await whatsappView() });
  } catch (error) {
    console.error('Admin WhatsApp connect error:', error);
    res.status(400).json({ success: false, message: error.message || 'Could not start WhatsApp.' });
  }
};

exports.restartWhatsApp = async (req, res) => {
  try {
    await whatsapp.restart();
    await audit(req, 'whatsapp.restart');
    res.json({ success: true, whatsapp: await whatsappView() });
  } catch (error) {
    console.error('Admin WhatsApp restart error:', error);
    res.status(400).json({ success: false, message: error.message || 'Could not restart WhatsApp.' });
  }
};

exports.disconnectWhatsApp = async (req, res) => {
  try {
    const forget = req.body?.forget === true;
    await whatsapp.stop({ forget });
    await audit(req, forget ? 'whatsapp.disconnect_and_forget' : 'whatsapp.stop');
    res.json({ success: true, whatsapp: await whatsappView() });
  } catch (error) {
    console.error('Admin WhatsApp disconnect error:', error);
    res.status(500).json({ success: false, message: 'Could not disconnect WhatsApp.' });
  }
};
