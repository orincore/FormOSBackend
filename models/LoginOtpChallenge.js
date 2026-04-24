const mongoose = require('mongoose');

const loginOtpChallengeSchema = new mongoose.Schema({
  email: { type: String, required: true, lowercase: true, trim: true },
  codeHash: { type: String, required: true },
  expiresAt: { type: Date, required: true, index: { expires: 0 } },
  used: { type: Boolean, default: false },
}, { timestamps: true });

module.exports = mongoose.model('LoginOtpChallenge', loginOtpChallengeSchema);
