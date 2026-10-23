const crypto = require('crypto');
const User = require('../models/User');
const WhatsAppOtp = require('../models/WhatsAppOtp');
const WhatsAppOtpLog = require('../models/WhatsAppOtpLog');
const wa = require('../services/whatsappService');
const Document = require('../models/Document');
const StorageService = require('../services/storageService');
const { unlockDataKey, decryptFileEnvelope } = require('../services/vaultCrypto');

const OTP_TTL_MS = 10 * 60 * 1000;
const RESEND_GAP_MS = 60 * 1000;
const MAX_SENDS = 5;
const MAX_ATTEMPTS = 5;
const MAX_CODES_PER_NUMBER_HOUR = 3;
const MAX_CODES_PER_NUMBER_DAY = 6;

// Accepts "98765 43210", "+91 98765 43210", "09876543210" or "919876543210" and returns digits with the
// country code (919876543210). A number from another country must be given with its +code.
function normalizeNumber(input) {
  const raw = String(input || '').trim();
  const digits = raw.replace(/\D/g, '');
  if (!digits) return null;
  if (!raw.startsWith('+') && /^0?[6-9]\d{9}$/.test(digits)) return `91${digits.slice(-10)}`;
  if (/^91[6-9]\d{9}$/.test(digits)) return digits;
  if (raw.startsWith('+') && /^[1-9]\d{9,14}$/.test(digits)) return digits;
  return null;
}

const maskNumber = (n) => (n ? `+${n.slice(0, n.length > 10 ? n.length - 10 : 0)} ${'*'.repeat(6)}${n.slice(-4)}`.trim() : null);

const hashCode = (userId, number, code) =>
  crypto.createHmac('sha256', process.env.JWT_SECRET).update(`${userId}:${number}:${code}`).digest('hex');

const safeEqual = (a, b) => {
  const x = Buffer.from(a); const y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};

exports.normalizeNumber = normalizeNumber;

exports.getStatus = async (req, res) => {
  try {
    const [user, pending] = await Promise.all([
      User.findById(req.userId).select('whatsapp securityVersion'),
      WhatsAppOtp.findOne({ userId: req.userId }),
    ]);
    const now = Date.now();
    const live = pending && pending.expiresAt.getTime() > now ? pending : null;
    res.json({
      success: true,
      bot: { online: wa.isReady(), number: wa.botNumber(), ...wa.publicProgress() },
      encrypted: { applies: user?.securityVersion === 2, allowed: user?.whatsapp?.allowEncryptedAccess === true },
      linked: user?.whatsapp?.number ? { number: maskNumber(user.whatsapp.number), verifiedAt: user.whatsapp.verifiedAt } : null,
      pending: live
        ? { number: maskNumber(live.number), expiresAt: live.expiresAt, resendAt: new Date(live.lastSentAt.getTime() + RESEND_GAP_MS), attemptsLeft: Math.max(0, MAX_ATTEMPTS - live.attempts) }
        : null,
    });
  } catch (error) {
    console.error('WhatsApp status error:', error);
    res.status(500).json({ success: false, message: 'Could not load your WhatsApp status.' });
  }
};

exports.startLink = async (req, res) => {
  try {
    // "resend" asks for a new code to the number already waiting for verification.
    const waiting = req.body?.resend === true ? await WhatsAppOtp.findOne({ userId: req.userId }) : null;
    const number = req.body?.resend === true ? waiting?.number : normalizeNumber(req.body?.phone);
    if (!number) {
      return res.status(400).json({ success: false, message: 'Enter a valid mobile number. For a number outside India, start with + and the country code.' });
    }
    if (wa.botNumber() && number === wa.botNumber()) {
      return res.status(400).json({ success: false, message: 'That is the number the assistant itself runs on. Enter the number you will message it from.' });
    }
    if (!wa.isReady()) {
      return res.status(503).json({ success: false, code: 'BOT_OFFLINE', message: 'The WhatsApp assistant is offline right now, so a code cannot be sent. Please try again later.' });
    }

    const taken = await User.findOne({ 'whatsapp.number': number }).select('_id');
    if (taken) {
      const mine = String(taken._id) === String(req.userId);
      return res.status(409).json({ success: false, message: mine ? 'This number is already linked to your account.' : 'This number is already linked to another FormOS account.' });
    }

    const existing = await WhatsAppOtp.findOne({ userId: req.userId });
    const now = Date.now();
    if (existing && existing.expiresAt.getTime() > now) {
      const wait = existing.lastSentAt.getTime() + RESEND_GAP_MS - now;
      if (wait > 0) return res.status(429).json({ success: false, code: 'RESEND_WAIT', message: `Please wait ${Math.ceil(wait / 1000)} seconds before asking for another code.`, retryAfterSeconds: Math.ceil(wait / 1000) });
      if (existing.number === number && existing.sentCount >= MAX_SENDS) return res.status(429).json({ success: false, message: 'Too many codes were sent to this number. Try again after a while.' });
    }

    // However many accounts ask, one number only ever receives a few codes. This is checked before any
    // message is sent, and says nothing about whether the number is on WhatsApp.
    const hourAgo = new Date(now - 3600 * 1000);
    const [lastHour, lastDay] = await Promise.all([
      WhatsAppOtpLog.countDocuments({ number, at: { $gte: hourAgo } }),
      WhatsAppOtpLog.countDocuments({ number }),
    ]);
    if (lastHour >= MAX_CODES_PER_NUMBER_HOUR || lastDay >= MAX_CODES_PER_NUMBER_DAY) {
      return res.status(429).json({ success: false, code: 'NUMBER_LIMIT', message: 'Too many codes have been sent to this number. Please try again later.' });
    }

    let onWhatsApp = false;
    try { onWhatsApp = await wa.isOnWhatsApp(number); } catch (error) {
      return res.status(503).json({ success: false, code: 'BOT_OFFLINE', message: 'The WhatsApp assistant is offline right now. Please try again later.' });
    }
    if (!onWhatsApp) {
      return res.status(422).json({ success: false, message: 'That number is not on WhatsApp. Check it and try again.' });
    }

    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    try {
      await wa.sendText(number, `Your FormOS verification code is *${code}*.\nIt works for 10 minutes. If you did not ask for it, ignore this message and do not share the code.`);
    } catch (error) {
      console.error('WhatsApp OTP send failed:', error.message);
      return res.status(502).json({ success: false, message: 'The code could not be sent on WhatsApp. Please try again.' });
    }

    await WhatsAppOtpLog.create({ number }).catch(() => {});
    const sameNumber = existing && existing.number === number;
    await WhatsAppOtp.findOneAndUpdate(
      { userId: req.userId },
      {
        number,
        codeHash: hashCode(req.userId, number, code),
        expiresAt: new Date(now + OTP_TTL_MS),
        attempts: 0,
        sentCount: sameNumber ? existing.sentCount + 1 : 1,
        lastSentAt: new Date(now),
      },
      { upsert: true, setDefaultsOnInsert: true }
    );

    res.json({ success: true, message: 'We sent a code to your WhatsApp.', pending: { number: maskNumber(number), expiresAt: new Date(now + OTP_TTL_MS), resendAt: new Date(now + RESEND_GAP_MS), attemptsLeft: MAX_ATTEMPTS } });
  } catch (error) {
    console.error('WhatsApp link start error:', error);
    res.status(500).json({ success: false, message: 'Could not start linking. Please try again.' });
  }
};

exports.verifyLink = async (req, res) => {
  try {
    const code = String(req.body?.code || '').replace(/\s/g, '');
    if (!/^\d{6}$/.test(code)) return res.status(400).json({ success: false, message: 'Enter the 6-digit code.' });

    const pending = await WhatsAppOtp.findOne({ userId: req.userId });
    if (!pending || pending.expiresAt.getTime() <= Date.now()) {
      return res.status(410).json({ success: false, code: 'CODE_EXPIRED', message: 'That code has expired. Ask for a new one.' });
    }
    if (pending.attempts >= MAX_ATTEMPTS) {
      await WhatsAppOtp.deleteOne({ _id: pending._id });
      return res.status(429).json({ success: false, code: 'CODE_LOCKED', message: 'Too many wrong codes. Ask for a new one.' });
    }

    // Count the attempt first, so concurrent guesses cannot beat the limit.
    const counted = await WhatsAppOtp.findOneAndUpdate({ _id: pending._id, attempts: { $lt: MAX_ATTEMPTS } }, { $inc: { attempts: 1 } }, { new: true });
    if (!counted) return res.status(429).json({ success: false, code: 'CODE_LOCKED', message: 'Too many wrong codes. Ask for a new one.' });

    if (!safeEqual(counted.codeHash, hashCode(req.userId, counted.number, code))) {
      const left = Math.max(0, MAX_ATTEMPTS - counted.attempts);
      if (left === 0) await WhatsAppOtp.deleteOne({ _id: counted._id });
      return res.status(400).json({ success: false, message: left ? `That code is not right. ${left} ${left === 1 ? 'try' : 'tries'} left.` : 'That code is not right. Ask for a new one.', attemptsLeft: left });
    }

    try {
      const result = await User.updateOne(
        { _id: req.userId },
        { $set: { 'whatsapp.number': counted.number, 'whatsapp.verifiedAt': new Date() } }
      );
      if (!result.matchedCount) return res.status(404).json({ success: false, message: 'Account not found.' });
    } catch (error) {
      if (error.code === 11000) return res.status(409).json({ success: false, message: 'This number was linked to another account a moment ago.' });
      throw error;
    }
    await WhatsAppOtp.deleteOne({ _id: counted._id });

    wa.sendText(counted.number, 'Your number is linked to FormOS. Send *help* to see what I can do, or just ask a question about your documents.').catch((e) => console.warn('WhatsApp welcome not sent:', e.message));

    res.json({ success: true, message: 'WhatsApp linked.', linked: { number: maskNumber(counted.number), verifiedAt: new Date() }, bot: { online: wa.isReady(), number: wa.botNumber() } });
  } catch (error) {
    console.error('WhatsApp verify error:', error);
    res.status(500).json({ success: false, message: 'Could not verify the code. Please try again.' });
  }
};

exports.cancelPending = async (req, res) => {
  await WhatsAppOtp.deleteOne({ userId: req.userId }).catch(() => {});
  res.json({ success: true });
};

exports.unlink = async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('whatsapp');
    const number = user?.whatsapp?.number;
    await User.updateOne({ _id: req.userId }, { $set: { 'whatsapp.number': null, 'whatsapp.verifiedAt': null } });
    await WhatsAppOtp.deleteOne({ userId: req.userId });
    if (number && wa.isReady()) wa.sendText(number, 'This number was unlinked from your FormOS account. I will not reply here any more.').catch(() => {});
    res.json({ success: true, message: 'WhatsApp unlinked.' });
  } catch (error) {
    console.error('WhatsApp unlink error:', error);
    res.status(500).json({ success: false, message: 'Could not unlink WhatsApp. Please try again.' });
  }
};

// Security V2 members choose whether the assistant may open their encrypted vault (with their PIN, in
// memory, for a few minutes). It is off by default and only a signed-in, freshly re-authenticated member
// can change it.
exports.setEncryptedAccess = async (req, res) => {
  try {
    const allow = req.body?.allow === true;
    const user = await User.findById(req.userId).select('securityVersion');
    if (!user) return res.status(404).json({ success: false, message: 'Account not found.' });
    if (user.securityVersion !== 2) return res.status(400).json({ success: false, message: 'This setting is only for accounts with device-side encryption.' });
    await User.updateOne({ _id: req.userId }, { $set: { 'whatsapp.allowEncryptedAccess': allow } });
    if (!allow) require('../services/whatsappBotService').closeVaultFor(req.userId); // takes effect at once
    res.json({ success: true, allowed: allow });
  } catch (error) {
    console.error('WhatsApp encrypted access error:', error);
    res.status(500).json({ success: false, message: 'Could not save that setting. Please try again.' });
  }
};

// ─── Send a stored document to the member's own WhatsApp ─────────────────────────────────────────
const MAX_PIN_FAILS = 5;
const PIN_LOCK_MS = 15 * 60 * 1000;
const MAX_FILE_BYTES = 16 * 1024 * 1024;

// Sends one stored file to the number this member verified, after checking their 6-digit PIN.
// It only ever sends to that number, never to one named in the request. The PIN is never logged or stored.
exports.sendDocument = async (req, res) => {
  const fail = (status, code, message, extra = {}) => res.status(status).json({ success: false, code, message, ...extra });
  try {
    const { documentId, pin } = req.body || {};
    if (!documentId || !/^[a-f0-9]{24}$/i.test(String(documentId))) return fail(400, 'BAD_REQUEST', 'Choose a document to send.');
    if (!/^\d{6}$/.test(String(pin || ''))) return fail(400, 'BAD_PIN_FORMAT', 'Enter your 6-digit PIN.');

    const user = await User.findById(req.userId);
    if (!user) return fail(404, 'NOT_FOUND', 'Account not found.');
    if (!user.whatsapp?.number) return fail(409, 'NOT_LINKED', 'Link your WhatsApp number first, then you can send documents to it.');
    if (!wa.isReady()) return fail(503, 'BOT_OFFLINE', 'The WhatsApp assistant is not connected right now. Try again in a moment.');

    const lockedUntil = user.whatsapp.pinLockedUntil;
    if (lockedUntil && lockedUntil > new Date()) {
      return fail(429, 'PIN_LOCKED', `Too many wrong PINs. Try again in ${Math.ceil((lockedUntil - Date.now()) / 60000)} minutes.`);
    }

    if (!(await user.comparePin(String(pin)))) {
      const after = await User.findOneAndUpdate({ _id: user._id }, { $inc: { 'whatsapp.pinFailures': 1 } }, { new: true });
      const failures = after?.whatsapp?.pinFailures || 1;
      if (failures >= MAX_PIN_FAILS) {
        await User.updateOne({ _id: user._id }, { $set: { 'whatsapp.pinFailures': 0, 'whatsapp.pinLockedUntil': new Date(Date.now() + PIN_LOCK_MS) } });
        return fail(429, 'PIN_LOCKED', 'Too many wrong PINs. Sending is locked for 15 minutes.');
      }
      const left = MAX_PIN_FAILS - failures;
      return fail(401, 'BAD_PIN', `That PIN is not right. ${left} ${left === 1 ? 'try' : 'tries'} left.`);
    }
    if (user.whatsapp.pinFailures) await User.updateOne({ _id: user._id }, { $set: { 'whatsapp.pinFailures': 0 } });

    const row = await Document.findOne({ _id: documentId, userId: req.userId });
    if (!row) return fail(404, 'NOT_FOUND', 'That document was not found.');

    const stored = await StorageService.downloadFile(row);
    let file;
    if (row.securityVersion === 2) {
      // Encrypted documents can only be opened here if the member agreed to it for the assistant.
      if (!user.whatsapp.allowEncryptedAccess) {
        return fail(403, 'ENCRYPTED_OFF', 'This document is encrypted on your device. Turn on encrypted access on the WhatsApp page to let FormOS send it.');
      }
      let key;
      try { key = await unlockDataKey(user, String(pin)); } catch { return fail(401, 'BAD_PIN', 'That PIN did not open your vault.'); }
      const opened = await decryptFileEnvelope(stored, key);
      file = { buffer: Buffer.from(opened.bytes), mimeType: opened.mimeType || row.mimeType, filename: opened.filename || 'document' };
    } else {
      file = { buffer: stored, mimeType: row.mimeType, filename: row.originalName };
    }
    if (file.buffer.length > MAX_FILE_BYTES) return fail(413, 'TOO_LARGE', 'That file is too large to send on WhatsApp. Download it instead.');

    await wa.sendMedia(user.whatsapp.number, file, file.filename);
    return res.json({ success: true, message: 'Sent. Check your WhatsApp.', number: maskNumber(user.whatsapp.number) });
  } catch (error) {
    if (error.code === 'BOT_OFFLINE') return res.status(503).json({ success: false, code: 'BOT_OFFLINE', message: error.message });
    if (error.code === 'NOT_ON_WHATSAPP') return res.status(422).json({ success: false, code: 'NOT_ON_WHATSAPP', message: error.message });
    console.error('WhatsApp send document error:', error.message);
    return res.status(500).json({ success: false, message: 'The document could not be sent. Try again.' });
  }
};
