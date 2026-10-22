const mongoose = require('mongoose');

// One row per verification code sent to a number, so a number cannot be flooded with codes by
// different accounts. Rows delete themselves after a day.
const whatsAppOtpLogSchema = new mongoose.Schema({
  number: { type: String, required: true, index: true },
  at: { type: Date, default: Date.now, expires: 24 * 3600 },
});

module.exports = mongoose.model('WhatsAppOtpLog', whatsAppOtpLogSchema);
