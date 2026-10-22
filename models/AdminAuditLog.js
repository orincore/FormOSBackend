const mongoose = require('mongoose');

// Append-only record of every administrative action. Details never contain secrets or
// personal document data, only what was done, to whom, and by whom.
const adminAuditLogSchema = new mongoose.Schema(
  {
    actorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    actorEmail: { type: String, required: true },
    action: { type: String, required: true, index: true },
    targetUserId: { type: mongoose.Schema.Types.ObjectId, default: null, index: true },
    targetEmail: { type: String, default: null },
    details: { type: mongoose.Schema.Types.Mixed, default: {} },
    ipHash: { type: String, default: '' },
  },
  { timestamps: { createdAt: true, updatedAt: false } }
);

adminAuditLogSchema.index({ createdAt: -1 });

module.exports = mongoose.model('AdminAuditLog', adminAuditLogSchema);
