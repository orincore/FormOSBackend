const validator = require('validator');
const User = require('../models/User');
const AuthSession = require('../models/AuthSession');
const Document = require('../models/Document');

// Emails are stored exactly as typed (trimmed + lowercased). Older accounts were saved
// through validator.normalizeEmail(), which strips dots from Gmail addresses, so lookups
// also try that form; both spellings reach the same inbox.
const canonicalEmail = (email) => String(email || '').trim().toLowerCase();

const emailCandidates = (email) => {
  const canonical = canonicalEmail(email);
  const legacy = validator.normalizeEmail(canonical) || canonical;
  return Array.from(new Set([canonical, legacy]));
};

const findUserByEmail = (email) => User.findOne({ email: { $in: emailCandidates(email) } });

// An account whose email was never verified cannot sign in, so it is the leftover of an
// abandoned registration. Remove it so the address can register again, unless it
// already holds documents. Returns false when the address is genuinely taken.
const releaseAbandonedAccount = async (existingUser) => {
  if (!existingUser) return true;
  if (existingUser.isVerified) return false;
  if (await Document.exists({ userId: existingUser._id })) return false;

  await AuthSession.deleteMany({ userId: existingUser._id });
  await User.deleteOne({ _id: existingUser._id });
  return true;
};

module.exports = { canonicalEmail, emailCandidates, findUserByEmail, releaseAbandonedAccount };
