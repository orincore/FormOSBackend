const mongoose = require('mongoose');

const pendingOAuthFlowSchema = new mongoose.Schema(
  {
    flowId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    provider: {
      type: String,
      enum: ['google', 'github'],
      required: true,
    },
    intent: {
      type: String,
      enum: ['login', 'signup', 'link'],
      required: true,
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null,
      index: true,
    },
    deviceId: String,
    deviceName: String,
    clientType: String,
    nonce: {
      type: String,
      required: true,
    },
    resultType: {
      type: String,
      enum: ['mfa', 'signup', 'linked', 'error'],
      default: null,
    },
    resultPayload: {
      type: mongoose.Schema.Types.Mixed,
      default: null,
    },
    consumedAt: {
      type: Date,
      default: null,
    },
    expiresAt: {
      type: Date,
      required: true,
      index: { expires: 0 },
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model('PendingOAuthFlow', pendingOAuthFlowSchema);
