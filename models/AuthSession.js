const mongoose = require('mongoose');

const authSessionSchema = new mongoose.Schema(
  {
    sessionId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    deviceId: {
      type: String,
      required: true,
      index: true,
    },
    deviceName: {
      type: String,
      default: 'Unknown device',
    },
    clientType: {
      type: String,
      enum: ['web', 'extension', 'mobile', 'unknown'],
      default: 'web',
    },
    userAgent: {
      type: String,
      default: '',
    },
    ipHash: {
      type: String,
      default: '',
    },
    trustedUntil: {
      type: Date,
      default: null,
    },
    lastAuthenticatedAt: {
      type: Date,
      default: Date.now,
    },
    lastStepUpAt: {
      type: Date,
      default: null,
    },
    stepUpExpiresAt: {
      type: Date,
      default: null,
    },
    lastSeenAt: {
      type: Date,
      default: Date.now,
    },
    revokedAt: {
      type: Date,
      default: null,
    },
    revokedReason: {
      type: String,
      default: null,
    },
  },
  { timestamps: true }
);

authSessionSchema.index({ userId: 1, deviceId: 1, revokedAt: 1 });

module.exports = mongoose.model('AuthSession', authSessionSchema);
