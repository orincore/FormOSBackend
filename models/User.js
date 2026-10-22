const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  phone: {
    type: String,
    sparse: true,
    unique: true
  },
  pin: {
    type: String,
    default: null
  },
  name: {
    type: String,
    required: true
  },
  isVerified: {
    type: Boolean,
    default: false,
    index: true,
  },
  // Authorization role. Only changed by a superadmin (or the make-admin script).
  role: {
    type: String,
    enum: ['user', 'admin', 'superadmin'],
    default: 'user',
    index: true,
  },
  // Suspended accounts cannot sign in and all their sessions are revoked.
  status: {
    type: String,
    enum: ['active', 'suspended'],
    default: 'active',
    index: true,
  },
  // Staff-only console password (bcrypt). Separate from the customer PIN so a leaked or
  // shared PIN can never open the admin console. Set from the command line, never via the API.
  adminPasswordHash: { type: String, default: null, select: true },
  adminPasswordSetAt: { type: Date, default: null },
  adminFailedLogins: { type: Number, default: 0 },
  adminLockedUntil: { type: Date, default: null },
  suspendedAt: { type: Date, default: null },
  suspendedReason: { type: String, default: null },
  suspendedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  emailVerifiedAt: {
    type: Date,
    default: null,
  },
  extractedData: {
    fullName: String,
    dateOfBirth: String,
    aadhaarNumber: String,
    panNumber: String,
    address: String,
    phone: String,
    email: String,
    fatherName: String,
    gender: String,
    passportNumber: String,
    drivingLicenseNumber: String,
    pincode: String,
    state: String,
    yearOfBirth: String,
    customFields: mongoose.Schema.Types.Mixed
  },
  // The phone the person chats with the FormOS WhatsApp assistant from. Set only after the
  // code sent to that number on WhatsApp has been entered, and unique across accounts.
  whatsapp: {
    number: { type: String, default: null },
    verifiedAt: { type: Date, default: null },
    // Wrong PIN guesses made in the chat when asking for full (unmasked) details.
    // Security V2 only: the member has agreed that the assistant may open their vault with their PIN
    // for a few minutes at a time. Off unless they turn it on in the app.
    allowEncryptedAccess: { type: Boolean, default: false },
    pinFailures: { type: Number, default: 0 },
    pinLockedUntil: { type: Date, default: null }
  },
  security: {
    mfa: {
      enabled: {
        type: Boolean,
        default: true
      },
      secretEncrypted: String,
      secretIv: String,
      secretAuthTag: String,
      backupCodeHashes: {
        type: [String],
        default: []
      },
      enabledAt: Date,
      lastVerifiedAt: Date,
      recoveryCodesGeneratedAt: Date,
      // Last accepted TOTP time step; codes at or below it are rejected (replay protection)
      lastUsedTotpStep: {
        type: Number,
        default: null
      },
      // Set by an administrator: the old authenticator and recovery codes are refused
      // until the user proves email access and enrolls a new authenticator.
      resetRequired: {
        type: Boolean,
        default: false
      },
      resetRequestedAt: Date,
      // Authenticator re-enrollment in progress (persisted so it survives restarts)
      pendingSecretEncrypted: String,
      pendingSecretIv: String,
      pendingSecretAuthTag: String,
      pendingSecretCreatedAt: Date
    }
  },
  authMethods: {
    localPin: {
      type: Boolean,
      default: true
    },
    google: {
      type: Boolean,
      default: false
    },
    github: {
      type: Boolean,
      default: false
    }
  },
  providers: {
    google: {
      providerId: String,
      email: String,
      emailVerified: {
        type: Boolean,
        default: false
      },
      linkedAt: Date,
      lastLoginAt: Date,
      avatarUrl: String
    },
    github: {
      providerId: String,
      username: String,
      email: String,
      emailVerified: {
        type: Boolean,
        default: false
      },
      linkedAt: Date,
      lastLoginAt: Date,
      avatarUrl: String,
      profileUrl: String
    }
  },
  securityVersion: {
    type: Number,
    enum: [1, 2],
    default: 1,
  },
  migrationStatus: {
    type: String,
    enum: ['pending', 'in_progress', 'partial', 'completed', 'failed'],
    default: 'pending',
  },
  encryptedProfile: {
    type: String,
    default: null,
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
  createdAt: {
    type: Date,
    default: Date.now
  }
}, { timestamps: true });

userSchema.index({ 'providers.google.providerId': 1 }, { unique: true, sparse: true });
userSchema.index({ 'providers.github.providerId': 1 }, { unique: true, sparse: true });

// Hash PIN before saving
const BCRYPT_HASH = /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/;

userSchema.pre('save', async function(next) {
  if (!this.isModified('pin')) return next();
  if (!this.pin) return next();
  // A 6-digit PIN can never look like a bcrypt hash, so a hash here was produced
  // upstream (signup stores a hash, not the PIN) and must not be hashed again.
  if (BCRYPT_HASH.test(this.pin)) return next();
  this.pin = await bcrypt.hash(this.pin, 10);
  next();
});

// Compare PIN method
userSchema.methods.comparePin = async function(candidatePin) {
  if (!this.pin) return false;
  return await bcrypt.compare(candidatePin, this.pin);
};

// Mask sensitive data
userSchema.methods.maskSensitiveData = function() {
  const masked = { ...this.extractedData };
  if (masked.aadhaarNumber) {
    masked.aadhaarNumber = '****' + masked.aadhaarNumber.slice(-4);
  }
  if (masked.panNumber) {
    masked.panNumber = '****' + masked.panNumber.slice(-4);
  }
  return masked;
};

userSchema.index({ 'whatsapp.number': 1 }, { unique: true, partialFilterExpression: { 'whatsapp.number': { $type: 'string' } } });

module.exports = mongoose.model('User', userSchema);
