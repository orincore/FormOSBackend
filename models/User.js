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
    customFields: mongoose.Schema.Types.Mixed
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
      recoveryCodesGeneratedAt: Date
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
userSchema.pre('save', async function(next) {
  if (!this.isModified('pin')) return next();
  if (!this.pin) return next();
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

module.exports = mongoose.model('User', userSchema);
