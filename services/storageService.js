const mongoose = require('mongoose');
const { GridFSBucket } = require('mongodb');
const fs = require('fs/promises');
const path = require('path');
const { isS3Configured, isR2Configured, putObject, uploadToS3, downloadFromS3, deleteFromS3 } = require('./s3Service');

let bucket;
const getGridFSBucket = () => {
  if (!bucket) {
    if (!mongoose.connection.db) {
      throw new Error('Database connection not established');
    }
    bucket = new GridFSBucket(mongoose.connection.db, {
      bucketName: 'documents'
    });
  }
  return bucket;
};

// GridFS Storage Core Methods
const uploadToGridFS = (fileBuffer, filename, mimeType) => {
  return new Promise((resolve, reject) => {
    try {
      const bucket = getGridFSBucket();
      const uploadStream = bucket.openUploadStream(filename, {
        contentType: mimeType
      });
      uploadStream.end(fileBuffer);
      uploadStream.on('finish', () => {
        resolve(uploadStream.id); // Returns the ObjectId directly
      });
      uploadStream.on('error', reject);
    } catch (err) {
      reject(err);
    }
  });
};

const downloadFromGridFS = (gridfsId) => {
  return new Promise((resolve, reject) => {
    try {
      const bucket = getGridFSBucket();
      const downloadStream = bucket.openDownloadStream(gridfsId);
      const chunks = [];
      downloadStream.on('data', (chunk) => chunks.push(chunk));
      downloadStream.on('end', () => resolve(Buffer.concat(chunks)));
      downloadStream.on('error', reject);
    } catch (err) {
      reject(err);
    }
  });
};

const deleteFromGridFS = async (gridfsId) => {
  const bucket = getGridFSBucket();
  await bucket.delete(gridfsId);
};

// Local storage helpers
const uploadLocal = async (fileBuffer, originalname) => {
  const uploadDir = process.env.UPLOAD_DIR || './uploads';
  // Ensure upload directory exists
  await fs.mkdir(uploadDir, { recursive: true });
  const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
  const filename = `document-${uniqueSuffix}${path.extname(originalname)}`;
  const filePath = path.join(uploadDir, filename);
  await fs.writeFile(filePath, fileBuffer);
  return { filePath, filename };
};

const downloadLocal = async (filePath) => {
  return await fs.readFile(filePath);
};

const deleteLocal = async (filePath) => {
  await fs.unlink(filePath);
};

// Unified Storage Service Object
const StorageService = {
  uploadFile: async (buffer, filename, mimetype, userId, useGridFS) => {
    if (useGridFS) {
      const gridfsId = await uploadToGridFS(buffer, filename, mimetype);
      return {
        storageType: 'gridfs',
        gridfsId,
        fileSize: buffer.length
      };
    } else if (isS3Configured()) {
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
      const cleanFilename = `document-${uniqueSuffix}${path.extname(filename)}`;
      const s3Result = await uploadToS3(buffer, cleanFilename, mimetype, userId);
      return {
        storageType: 's3',
        s3Key: s3Result.key,
        s3Location: s3Result.location,
        filePath: s3Result.key,
        fileSize: buffer.length
      };
    } else {
      const localResult = await uploadLocal(buffer, filename);
      return {
        storageType: 'local',
        filePath: localResult.filePath,
        filename: localResult.filename,
        fileSize: buffer.length
      };
    }
  },

  downloadFile: async (document) => {
    if (document.securityVersion === 2 && !['gridfs', 'r2'].includes(document.storageType)) {
      throw new Error('Security Violation: Security V2 documents must use GridFS or R2 storage. S3/local fallback is blocked.');
    }

    if (document.storageType === 'gridfs') {
      if (!document.gridfsId) {
        throw new Error('GridFS file ID is missing from document');
      }
      return await downloadFromGridFS(document.gridfsId);
    } else if (document.storageType === 'r2') {
      if (!document.s3Key) throw new Error('Storage key is missing from document');
      return await downloadFromS3(document.s3Key);
    } else if (document.storageType === 's3') {
      return await downloadFromS3(document.s3Key);
    } else if (document.storageType === 'local') {
      return await downloadLocal(document.filePath);
    } else {
      throw new Error(`Unsupported storage type: ${document.storageType}`);
    }
  },

  deleteFile: async (document) => {
    if (document.securityVersion === 2 && !['gridfs', 'r2'].includes(document.storageType)) {
      throw new Error('Security Violation: Security V2 documents must use GridFS or R2 storage. S3/local fallback is blocked.');
    }

    if (document.storageType === 'gridfs') {
      if (document.gridfsId) {
        await deleteFromGridFS(document.gridfsId);
      }
    } else if (document.storageType === 'r2') {
      if (document.s3Key) {
        await deleteFromS3(document.s3Key);
      }
    } else if (document.storageType === 's3') {
      if (document.s3Key) {
        await deleteFromS3(document.s3Key);
      }
    } else if (document.storageType === 'local') {
      if (document.filePath) {
        await deleteLocal(document.filePath);
      }
    }
  },

  // Stores an already-encrypted (Security V2) file: in Cloudflare R2 when it is set up, otherwise GridFS.
  // Only ciphertext may be passed in. Returns the fields to save on the document record.
  uploadEncrypted: async (buffer, mimeType, userId) => {
    if (isR2Configured()) {
      const key = `encrypted/${userId}/${Date.now()}-${Math.round(Math.random() * 1E9)}.bin`;
      await putObject(key, buffer, 'application/octet-stream');
      return { storageType: 'r2', s3Key: key, filePath: key, fileSize: buffer.length };
    }
    const gridfsId = await uploadToGridFS(buffer, 'encrypted_blob', mimeType);
    return { storageType: 'gridfs', gridfsId, filePath: gridfsId.toString(), fileSize: buffer.length };
  },

  // Removes whatever uploadEncrypted stored, for cleanup when saving the record fails.
  discardEncrypted: async (stored) => {
    if (stored.storageType === 'r2') await deleteFromS3(stored.s3Key);
    else await deleteFromGridFS(stored.gridfsId);
  },

  // Export raw GridFS functions for transaction/cleanup handling
  uploadToGridFS,
  deleteFromGridFS
};

module.exports = StorageService;
