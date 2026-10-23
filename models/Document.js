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
  // For a standard copy made when an account moved off Security V2: the encrypted original it was made from.
  migratedFrom: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Document'
  },
  // When the AI read this document and its data was saved. Documents without it were saved by the older reader.
  aiReadAt: {
    type: Date
  },
  // A small picture of a photo or scan (data URL), so lists can show what the document looks like. Standard documents only.
  thumbnail: {
    type: String
  },
  documentType: {
    type: String,
    enum: ['aadhaar', 'pan', 'passport', 'license', 'other'],
    default: 'other'
  },
  ocrStatus: {
    type: String,
    enum: ['pending', 'processing', 'completed', 'failed', 'skipped'],
    default: 'pending'
  },
  extractedText: {
    type: String
  },
  structuredData: {
    type: mongoose.Schema.Types.Mixed
  },
  // When the document's own labelled fields (vehicle class, roll no, marks...) were last read. Older documents get it on demand.
  fieldsExtractedAt: {
    type: Date,
    default: null
  },
  // When the member confirmed (or corrected) what kind of document this is, in the WhatsApp chat.
  typeConfirmedAt: {
    type: Date,
    default: null
  },
  // S3 specific fields
  storageType: {
    type: String,
    enum: ['local', 's3', 'gridfs', 'r2'],
    default: 'local'
  },
  s3Key: {
    type: String
  },
  s3Location: {
    type: String
  },
  securityVersion: {
    type: Number,
    enum: [1, 2],
    default: 1,
  },
  encryptionVersion: {
    type: Number,
    default: 0,
  },
  gridfsId: {
    type: mongoose.Schema.Types.ObjectId,
    default: null,
  },
  encryptedText: {
    type: String,
    default: null,
  },
  encryptedStructuredData: {
    type: String,
    default: null,
  },
  uploadedAt: {
    type: Date,
    default: Date.now
  }
}, { timestamps: true });

module.exports = mongoose.model('Document', documentSchema);
