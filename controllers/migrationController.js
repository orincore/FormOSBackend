const User = require('../models/User');
const Document = require('../models/Document');
const StorageService = require('../services/storageService');
const mongoose = require('mongoose');

exports.migrateProfile = async (req, res) => {
  try {
    const { encryptedProfile, userSalt, wrappedUserKey } = req.body;
    if (!encryptedProfile || !userSalt || !wrappedUserKey) {
      return res.status(400).json({
        success: false,
        message: 'Missing V2 profile cryptographic payloads'
      });
    }

    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Set user migration fields
    user.encryptedProfile = typeof encryptedProfile === 'object' ? JSON.stringify(encryptedProfile) : encryptedProfile;
    user.userSalt = userSalt;
    user.wrappedUserKey = typeof wrappedUserKey === 'object' ? JSON.stringify(wrappedUserKey) : wrappedUserKey;
    user.migrationStatus = 'in_progress';
    user.extractedData = {}; // Evict plaintext V1 fields from backend memory context
    await user.save();

    return res.json({
      success: true,
      message: 'Profile migrated to V2 successfully. Migration status: in_progress.'
    });
  } catch (error) {
    console.error('Profile migration error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error migrating profile data'
    });
  }
};

exports.uploadDocumentMigration = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No file uploaded'
      });
    }

    const documentId = req.params.id;
    const document = await Document.findOne({ _id: documentId, userId: req.userId });
    if (!document) {
      return res.status(404).json({
        success: false,
        message: 'Document not found'
      });
    }

    const fileBuffer = req.file.buffer;

    // Validate V2 file envelope header
    if (fileBuffer.length < 4) {
      return res.status(400).json({
        success: false,
        message: 'Invalid file envelope format'
      });
    }

    const headerLength = fileBuffer.readUInt32BE(0);
    if (fileBuffer.length < 4 + headerLength) {
      return res.status(400).json({
        success: false,
        message: 'Invalid file envelope header length'
      });
    }

    const headerBytes = fileBuffer.subarray(4, 4 + headerLength);
    const headerJSON = headerBytes.toString('utf8');
    const parsedHeader = JSON.parse(headerJSON);

    if (parsedHeader.v !== 'formos_v2_file_aes_gcm') {
      return res.status(400).json({
        success: false,
        message: 'Invalid V2 file envelope tag'
      });
    }

    // Upload to GridFS as a temporary file
    const tempGridfsId = await StorageService.uploadToGridFS(
      fileBuffer,
      'temp_migration_blob',
      parsedHeader.mimeType
    );

    return res.json({
      success: true,
      tempGridfsId: tempGridfsId.toString(),
      message: 'Document encrypted envelope uploaded successfully. Verification required.'
    });
  } catch (error) {
    console.error('Document migration upload error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error uploading document encrypted envelope'
    });
  }
};

exports.downloadTempDocument = async (req, res) => {
  try {
    const { tempGridfsId } = req.params;
    const fileId = new mongoose.Types.ObjectId(tempGridfsId);
    
    // Download raw temp GridFS file
    const fileBuffer = await StorageService.downloadFile({
      storageType: 'gridfs',
      gridfsId: fileId
    });

    res.setHeader('Content-Type', 'application/octet-stream');
    return res.send(fileBuffer);
  } catch (error) {
    console.error('Download temp document error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error downloading temp document'
    });
  }
};

exports.commitDocumentMigration = async (req, res) => {
  try {
    const { tempGridfsId } = req.body;
    const documentId = req.params.id;

    if (!tempGridfsId) {
      return res.status(400).json({
        success: false,
        message: 'Missing temporary GridFS ID'
      });
    }

    const document = await Document.findOne({ _id: documentId, userId: req.userId });
    if (!document) {
      return res.status(404).json({
        success: false,
        message: 'Document not found'
      });
    }

    if (document.securityVersion === 2) {
      // Already migrated, cleanup the temp file to prevent orphan leaks
      await StorageService.deleteFromGridFS(new mongoose.Types.ObjectId(tempGridfsId)).catch(console.error);
      return res.json({
        success: true,
        message: 'Document was already migrated'
      });
    }

    // Delete the legacy V1 file from S3 / Local storage
    try {
      await StorageService.deleteFile(document);
    } catch (cleanupErr) {
      console.warn('⚠️ Legacy file cleanup failed during migration for key/path:', document.s3Key || document.filePath);
    }

    // Update document record to V2 in-place
    document.securityVersion = 2;
    document.storageType = 'gridfs';
    document.gridfsId = new mongoose.Types.ObjectId(tempGridfsId);
    document.filePath = tempGridfsId;
    document.filename = 'Encrypted File';
    document.originalName = 'encrypted_file';
    document.ocrStatus = 'skipped';
    await document.save();

    return res.json({
      success: true,
      message: 'Document committed to secure storage successfully.'
    });
  } catch (error) {
    console.error('Commit document migration error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error committing document migration'
    });
  }
};

exports.completeMigration = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Check if there are any remaining V1 documents
    const v1DocsCount = await Document.countDocuments({
      userId: req.userId,
      securityVersion: 1
    });

    if (v1DocsCount === 0) {
      user.securityVersion = 2;
      user.migrationStatus = 'completed';
    } else {
      user.migrationStatus = 'partial';
    }

    await user.save();

    return res.json({
      success: true,
      migrationStatus: user.migrationStatus,
      securityVersion: user.securityVersion,
      remainingV1Documents: v1DocsCount
    });
  } catch (error) {
    console.error('Complete migration error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error completing migration'
    });
  }
};

exports.failMigration = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    user.migrationStatus = 'failed';
    await user.save();

    return res.json({
      success: true,
      migrationStatus: user.migrationStatus
    });
  } catch (error) {
    console.error('Fail migration error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error flagging migration failure'
    });
  }
};
