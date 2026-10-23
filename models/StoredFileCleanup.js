const mongoose = require('mongoose');

// A stored file that could not be removed when its document was deleted (the bucket was unreachable, for example). The record of the
// document is gone, so this keeps just enough to find the file again and retry until it is really removed. It holds no personal data.
const schema = new mongoose.Schema(
  {
    storageType: { type: String, required: true },
    securityVersion: { type: Number, default: 1 },
    s3Key: { type: String, default: null },
    gridfsId: { type: mongoose.Schema.Types.ObjectId, default: null },
    filePath: { type: String, default: null },
    attempts: { type: Number, default: 0 },
    lastError: { type: String, default: '' },
  },
  { timestamps: true }
);

module.exports = mongoose.model('StoredFileCleanup', schema);
