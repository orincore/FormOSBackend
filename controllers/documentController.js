const fs = require('fs').promises;
const path = require('path');
const os = require('os');
const Document = require('../models/Document');
const User = require('../models/User');
const ocrService = require('../services/ocrService');
const { isS3Configured, downloadFromS3, deleteFromS3 } = require('../services/s3Service');
const { maskSensitiveText, maskStructuredData } = require('../services/securityService');
const StorageService = require('../services/storageService');
const { flags } = require('../config/featureFlags');

const serializeDocument = (document, { reveal = false } = {}) => ({
  id: document._id,
  originalName: document.originalName,
  documentType: document.documentType,
  fileSize: document.fileSize,
  mimeType: document.mimeType,
  ocrStatus: document.ocrStatus,
  storageType: document.storageType,
  uploadedAt: document.uploadedAt,
  structuredData: reveal
    ? document.structuredData || {}
    : maskStructuredData(document.structuredData || {}),
  extractedText: reveal ? document.extractedText || '' : maskSensitiveText(document.extractedText || ''),
  ...(document.securityVersion === 2 ? {
    encryptedText: document.encryptedText || null,
    encryptedStructuredData: document.encryptedStructuredData || null,
    securityVersion: 2
  } : {
    securityVersion: 1
  })
});

exports.uploadDocument = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No file uploaded',
      });
    }

    const { documentType } = req.body;
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Check if this is a V2 encrypted envelope
    let isV2Envelope = false;
    let header = null;
    const fileBuffer = req.file.buffer;

    if (fileBuffer && fileBuffer.length >= 4) {
      const headerLength = fileBuffer.readUInt32BE(0);
      if (fileBuffer.length >= 4 + headerLength) {
        try {
          const headerBytes = fileBuffer.subarray(4, 4 + headerLength);
          const headerJSON = headerBytes.toString('utf8');
          const parsedHeader = JSON.parse(headerJSON);
          if (
            parsedHeader.v === 'formos_v2_file_aes_gcm' &&
            parsedHeader.encryptionVersion === 1 &&
            parsedHeader.algorithm === 'AES-GCM'
          ) {
            isV2Envelope = true;
            header = parsedHeader;
          }
        } catch (e) {
          // Not a valid V2 envelope structure
        }
      }
    }

    const useGridFS = flags.GRIDFS_ENABLED && user.securityVersion === 2 && isV2Envelope;

    // Guard rails:
    // 1. If V1 user tries to upload a V2 envelope -> reject
    if (isV2Envelope && user.securityVersion !== 2) {
      return res.status(403).json({
        success: false,
        message: 'V1 users are not allowed to upload encrypted V2 documents.'
      });
    }
    // 2. If V2 envelope is submitted but GRIDFS_ENABLED is false -> reject
    if (isV2Envelope && !flags.GRIDFS_ENABLED) {
      return res.status(403).json({
        success: false,
        message: 'Secure GridFS storage is currently disabled.'
      });
    }

    if (useGridFS) {
      // Opaque GridFS V2 upload path
      const gridfsId = await StorageService.uploadToGridFS(fileBuffer, 'encrypted_blob', header.mimeType);

      const document = new Document({
        userId: req.userId,
        filename: 'Encrypted File', // Mask original filename
        originalName: 'encrypted_file', // Mask original filename
        filePath: gridfsId.toString(),
        fileSize: fileBuffer.length,
        mimeType: header.mimeType,
        documentType: documentType || 'other',
        ocrStatus: 'skipped', // Skip server-side OCR
        storageType: 'gridfs',
        gridfsId: gridfsId,
        securityVersion: 2,
        encryptionVersion: 1
      });

      try {
        await document.save();
      } catch (dbErr) {
        console.log('⚠️ MongoDB save failed, initiating GridFS cleanup for ID:', gridfsId);
        // Cleanup transaction: Delete GridFS file if MongoDB record fails
        await StorageService.deleteFromGridFS(gridfsId).catch(console.error);
        throw dbErr;
      }

      return res.status(201).json({
        success: true,
        message: 'Document uploaded successfully to secure storage',
        document: serializeDocument(document),
      });
    }

    // Plaintext V1 upload path
    // Validate that V2 user cannot upload plaintext
    if (user.securityVersion === 2) {
      return res.status(403).json({
        success: false,
        code: 'V2_PLAINTEXT_UPLOAD_BLOCKED',
        message: 'Security V2 accounts are blocked from uploading plaintext documents.'
      });
    }

    const uploadResult = await StorageService.uploadFile(
      fileBuffer,
      req.file.originalname,
      req.file.mimetype,
      req.userId,
      false
    );

    const document = await Document.create({
      userId: req.userId,
      filename: uploadResult.filename || uploadResult.s3Key,
      originalName: req.file.originalname,
      filePath: uploadResult.filePath,
      fileSize: uploadResult.fileSize,
      mimeType: req.file.mimetype,
      documentType: documentType || 'other',
      ocrStatus: 'pending',
      storageType: uploadResult.storageType,
      s3Key: uploadResult.s3Key || null,
      s3Location: uploadResult.s3Location || null,
      securityVersion: 1,
      encryptionVersion: 0
    });

    const useS3 = isS3Configured();
    processOCR(document._id, uploadResult.filePath, req.userId, useS3);

    return res.status(201).json({
      success: true,
      message: 'Document uploaded successfully',
      document: serializeDocument(document),
    });
  } catch (error) {
    console.error('Upload error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error uploading document',
    });
  }
};

exports.uploadSecureV2Document = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No file uploaded',
      });
    }

    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Reject non-V2 users
    if (user.securityVersion !== 2) {
      return res.status(403).json({
        success: false,
        message: 'This secure V2 path is reserved for Security V2 accounts only.'
      });
    }

    const fileBuffer = req.file.buffer;

    // Validate V2 file envelope header
    if (!fileBuffer || fileBuffer.length < 4) {
      return res.status(400).json({
        success: false,
        message: 'Invalid secure V2 file envelope format'
      });
    }

    const headerLength = fileBuffer.readUInt32BE(0);
    if (fileBuffer.length < 4 + headerLength) {
      return res.status(400).json({
        success: false,
        message: 'Invalid secure V2 file envelope header length'
      });
    }

    const headerBytes = fileBuffer.subarray(4, 4 + headerLength);
    const headerJSON = headerBytes.toString('utf8');
    let header;
    try {
      header = JSON.parse(headerJSON);
    } catch (e) {
      return res.status(400).json({
        success: false,
        message: 'Invalid secure V2 file envelope header JSON'
      });
    }

    if (
      header.v !== 'formos_v2_file_aes_gcm' ||
      header.encryptionVersion !== 1 ||
      header.algorithm !== 'AES-GCM'
    ) {
      return res.status(400).json({
        success: false,
        message: 'Invalid secure V2 envelope tags'
      });
    }

    // Upload to GridFS
    const gridfsId = await StorageService.uploadToGridFS(fileBuffer, 'encrypted_blob', header.mimeType);

    // Save V2 Document record
    const document = new Document({
      userId: req.userId,
      filename: 'Encrypted File',
      originalName: 'encrypted_file',
      filePath: gridfsId.toString(),
      fileSize: fileBuffer.length,
      mimeType: header.mimeType,
      documentType: req.body.documentType || 'other',
      ocrStatus: 'skipped', // Skip server-side OCR
      storageType: 'gridfs',
      gridfsId: gridfsId,
      securityVersion: 2,
      encryptionVersion: 1
    });

    try {
      await document.save();
    } catch (dbErr) {
      console.error('⚠️ MongoDB save failed, initiating GridFS cleanup for ID:', gridfsId);
      await StorageService.deleteFromGridFS(gridfsId).catch(console.error);
      throw dbErr;
    }

    return res.status(201).json({
      success: true,
      message: 'Document uploaded successfully to secure storage',
      document: serializeDocument(document),
    });
  } catch (error) {
    console.error('Secure V2 upload error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error uploading secure V2 document',
    });
  }
};

async function processOCR(documentId, filePathOrKey, userId, useS3 = false) {
  try {
    await Document.findByIdAndUpdate(documentId, { ocrStatus: 'processing' });

    let filePath = filePathOrKey;
    let tempFilePath = null;

    if (useS3) {
      const fileBuffer = await downloadFromS3(filePathOrKey);
      tempFilePath = path.join(os.tmpdir(), `temp-${Date.now()}-${path.basename(filePathOrKey)}`);
      await fs.writeFile(tempFilePath, fileBuffer);
      filePath = tempFilePath;
    }

    const extractedText = await ocrService.extractText(filePath);
    const structuredData = ocrService.parseStructuredData(extractedText);

    if (structuredData.address) {
      const formAnalyzerService = require('../services/formAnalyzerService');
      const addressComponents = formAnalyzerService.parseAddress(structuredData.address);
      Object.assign(structuredData, addressComponents);
    }

    await Document.findByIdAndUpdate(documentId, {
      extractedText,
      structuredData,
      ocrStatus: 'completed',
    });

    const user = await User.findById(userId);
    user.extractedData = {
      ...(user.extractedData || {}),
      ...structuredData,
    };
    await user.save();

    if (tempFilePath) {
      await fs.unlink(tempFilePath).catch(console.error);
    }

    console.log(`OCR completed for document ${documentId}`);
  } catch (error) {
    console.error('OCR processing error:', error);
    await Document.findByIdAndUpdate(documentId, {
      ocrStatus: 'failed',
    });
  }
}

exports.getDocuments = async (req, res) => {
  try {
    const documents = await Document.find({ userId: req.userId }).sort({ uploadedAt: -1 });

    return res.json({
      success: true,
      documents: documents.map((document) => serializeDocument(document)),
    });
  } catch (error) {
    console.error('Get documents error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error fetching documents',
    });
  }
};

exports.getDocument = async (req, res) => {
  try {
    const document = await Document.findOne({
      _id: req.params.id,
      userId: req.userId,
    });

    if (!document) {
      return res.status(404).json({
        success: false,
        message: 'Document not found',
      });
    }

    return res.json({
      success: true,
      document: serializeDocument(document),
    });
  } catch (error) {
    console.error('Get document error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error fetching document',
    });
  }
};

exports.revealDocument = async (req, res) => {
  try {
    const document = await Document.findOne({
      _id: req.params.id,
      userId: req.userId,
    });

    if (!document) {
      return res.status(404).json({
        success: false,
        message: 'Document not found',
      });
    }

    return res.json({
      success: true,
      document: serializeDocument(document, { reveal: true }),
    });
  } catch (error) {
    console.error('Reveal document error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error revealing document',
    });
  }
};

exports.downloadDocument = async (req, res) => {
  try {
    const document = await Document.findOne({
      _id: req.params.id,
      userId: req.userId,
    });

    if (!document) {
      return res.status(404).json({
        success: false,
        message: 'Document not found',
      });
    }

    if (document.storageType === 'gridfs') {
      const fileBuffer = await StorageService.downloadFile(document);
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Disposition', 'attachment; filename="encrypted_document"');
      return res.send(fileBuffer);
    }

    const fileBuffer = document.storageType === 's3' && document.s3Key
      ? await downloadFromS3(document.s3Key)
      : await fs.readFile(document.filePath);

    res.setHeader('Content-Type', document.mimeType);
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(document.originalName)}"`);
    return res.send(fileBuffer);
  } catch (error) {
    console.error('Download document error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error downloading document',
    });
  }
};

exports.updateStructuredData = async (req, res) => {
  try {
    const { structuredData, encryptedText, encryptedStructuredData } = req.body;
    const user = await User.findById(req.userId);
    const isV2 = user && user.securityVersion === 2;

    const updateFields = {};
    if (isV2) {
      if (encryptedText !== undefined) updateFields.encryptedText = encryptedText;
      if (encryptedStructuredData !== undefined) updateFields.encryptedStructuredData = encryptedStructuredData;
      if (encryptedText) updateFields.ocrStatus = 'completed';
    } else {
      if (structuredData !== undefined) updateFields.structuredData = structuredData;
    }

    const document = await Document.findOneAndUpdate(
      { _id: req.params.id, userId: req.userId },
      updateFields,
      { new: true }
    );

    if (!document) {
      return res.status(404).json({
        success: false,
        message: 'Document not found',
      });
    }

    // For V1 users, also sync to user.extractedData
    if (!isV2 && structuredData) {
      user.extractedData = {
        ...(user.extractedData || {}),
        ...structuredData,
      };
      await user.save();
    }

    return res.json({
      success: true,
      message: 'Data updated successfully',
      document: serializeDocument(document, { reveal: !isV2 }),
    });
  } catch (error) {
    console.error('Update structured data error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error updating data',
    });
  }
};

exports.deleteDocument = async (req, res) => {
  try {
    const document = await Document.findOne({
      _id: req.params.id,
      userId: req.userId,
    });

    if (!document) {
      return res.status(404).json({
        success: false,
        message: 'Document not found',
      });
    }

    // Delete from S3, GridFS, or local filesystem
    if (document.storageType === 'gridfs') {
      await StorageService.deleteFile(document).catch((err) =>
        console.error('GridFS delete error (non-fatal):', err.message)
      );
    } else if (document.storageType === 's3' && document.s3Key) {
      await deleteFromS3(document.s3Key).catch((err) =>
        console.error('S3 delete error (non-fatal):', err.message)
      );
    } else if (document.filePath) {
      await fs.unlink(document.filePath).catch((err) =>
        console.error('Local file delete error (non-fatal):', err.message)
      );
    }

    // Remove from DB
    await document.deleteOne();

    // Rebuild user extractedData from remaining documents so profile stays accurate
    const remainingDocs = await Document.find({
      userId: req.userId,
      ocrStatus: 'completed',
    }).select('structuredData');

    const merged = {};
    for (const doc of remainingDocs) {
      if (doc.structuredData) Object.assign(merged, doc.structuredData);
    }

    await User.findByIdAndUpdate(req.userId, { extractedData: merged });

    return res.json({
      success: true,
      message: 'Document deleted successfully',
    });
  } catch (error) {
    console.error('Delete document error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error deleting document',
    });
  }
};

exports.getSecureV2Document = async (req, res) => {
  try {
    const document = await Document.findOne({
      _id: req.params.id,
      userId: req.userId
    });

    if (!document) {
      return res.status(404).json({
        success: false,
        message: 'Document not found'
      });
    }

    const user = await User.findById(req.userId);
    if (!user || user.securityVersion !== 2 || document.securityVersion !== 2) {
      return res.status(403).json({
        success: false,
        message: 'This secure V2 path is reserved for Security V2 accounts only.'
      });
    }

    return res.json({
      success: true,
      document: {
        id: document._id,
        originalName: document.originalName,
        mimeType: document.mimeType,
        fileSize: document.fileSize,
        uploadedAt: document.uploadedAt,
        encryptedText: document.encryptedText || null,
        encryptedStructuredData: document.encryptedStructuredData || null,
        securityVersion: 2
      }
    });
  } catch (error) {
    console.error('Secure V2 document retrieval error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error retrieving secure V2 document data'
    });
  }
};

exports.updateSecureV2Document = async (req, res) => {
  try {
    const { encryptedText, encryptedStructuredData } = req.body;
    const document = await Document.findOne({
      _id: req.params.id,
      userId: req.userId
    });

    if (!document) {
      return res.status(404).json({
        success: false,
        message: 'Document not found'
      });
    }

    const user = await User.findById(req.userId);
    if (!user || user.securityVersion !== 2 || document.securityVersion !== 2) {
      return res.status(403).json({
        success: false,
        message: 'This secure V2 path is reserved for Security V2 accounts only.'
      });
    }

    const updateFields = {};
    if (encryptedText !== undefined) updateFields.encryptedText = encryptedText;
    if (encryptedStructuredData !== undefined) updateFields.encryptedStructuredData = encryptedStructuredData;
    if (encryptedText) updateFields.ocrStatus = 'completed';

    const updatedDoc = await Document.findByIdAndUpdate(
      req.params.id,
      updateFields,
      { new: true }
    );

    return res.json({
      success: true,
      message: 'Secure V2 document updated successfully',
      document: {
        id: updatedDoc._id,
        originalName: updatedDoc.originalName,
        mimeType: updatedDoc.mimeType,
        fileSize: updatedDoc.fileSize,
        uploadedAt: updatedDoc.uploadedAt,
        encryptedText: updatedDoc.encryptedText || null,
        encryptedStructuredData: updatedDoc.encryptedStructuredData || null,
        securityVersion: 2
      }
    });
  } catch (error) {
    console.error('Secure V2 document update error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error updating secure V2 document'
    });
  }
};
