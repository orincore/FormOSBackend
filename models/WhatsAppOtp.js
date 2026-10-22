const mongoose = require('mongoose');

// One pending WhatsApp verification per account. The code is stored only as an HMAC, and the
// record deletes itself shortly after it expires.
const whatsAppOtpSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
    number: { type: String, required: true },
    codeHash: { type: String, required: true },
    expiresAt: { type: Date, required: true },
    attempts: { type: Number, default: 0 },
    sentCount: { type: Number, default: 1 },
    lastSentAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

whatsAppOtpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 600 });

module.exports = mongoose.model('WhatsAppOtp', whatsAppOtpSchema);
