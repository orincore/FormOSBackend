const mongoose = require('mongoose');

const documentSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  filename: {
    type: String,
    required: true
  },
  originalName: {
    type: String,
    required: true
  },
  filePath: {
    type: String,
    required: true
  },
  fileSize: {
    type: Number,
    required: true
  },
  mimeType: {
    type: String,
    required: true
  },
  documentType: {
    type: String,
    enum: ['aadhaar', 'pan', 'passport', 'license', 'other'],
    default: 'other'
  },
  ocrStatus: {
    type: String,
    enum: ['pending', 'processing', 'completed', 'failed'],
    default: 'pending'
  },
  extractedText: {
    type: String
  },
  structuredData: {
    type: mongoose.Schema.Types.Mixed
  },
  // S3 specific fields
  storageType: {
    type: String,
    enum: ['local', 's3'],
    default: 'local'
  },
  s3Key: {
    type: String
  },
  s3Location: {
    type: String
  },
  uploadedAt: {
    type: Date,
    default: Date.now
  }
}, { timestamps: true });

module.exports = mongoose.model('Document', documentSchema);
