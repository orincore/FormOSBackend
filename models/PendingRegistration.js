const mongoose = require('mongoose');

const pendingRegistrationSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    name: {
      type: String,
      required: true,
      trim: true,
    },
    phone: {
      type: String,
      default: '',
    },
    authMode: {
      type: String,
      enum: ['local', 'oauth'],
      default: 'local',
    },
    // bcrypt hash of the chosen PIN; the plain PIN is never stored
    pinHash: {
      type: String,
      default: null,
    },
    emailVerificationCodeHash: {
      type: String,
      required: true,
    },
    emailVerificationExpiresAt: {
      type: Date,
      required: true,
    },
    emailVerificationSentAt: {
      type: Date,
      default: Date.now,
    },
    emailVerifiedAt: {
      type: Date,
      default: null,
    },
    security: {
      mfa: {
        secretEncrypted: String,
        secretIv: String,
        secretAuthTag: String,
        verifiedAt: {
          type: Date,
          default: null,
        },
        lastUsedTotpStep: {
          type: Number,
          default: null,
        },
      },
      recoveryCodeHashes: {
        type: [String],
        default: [],
      },
      recoveryCodesGeneratedAt: {
        type: Date,
        default: null,
      },
      recoveryCodesConfirmedAt: {
        type: Date,
        default: null,
      },
    },
    oauth: {
      provider: {
        type: String,
        enum: ['google', 'github'],
        default: null,
      },
      providerId: String,
      providerEmail: String,
      providerEmailVerified: {
        type: Boolean,
        default: false,
      },
      providerUsername: String,
      avatarUrl: String,
      profileUrl: String,
    },
    securityVersion: {
      type: Number,
      enum: [1, 2],
      default: 1
    },
    userSalt: {
      type: String,
      default: null,
    },
    recoverySalt: {
      type: String,
      default: null,
    },
    wrappedUserKey: {
      type: String,
      default: null,
    },
    wrappedUserKeyRecovery: {
      type: String,
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

pendingRegistrationSchema.pre('validate', function(next) {
  if (this.authMode === 'local' && !this.pinHash) {
    return next(new Error('PIN data is required for local registrations'));
  }

  return next();
});

module.exports = mongoose.model('PendingRegistration', pendingRegistrationSchema);
