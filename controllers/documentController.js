const fs = require('fs').promises;
const path = require('path');
const os = require('os');
const Document = require('../models/Document');
const User = require('../models/User');
const ocrService = require('../services/ocrService');
const { isS3Configured, isR2Configured, downloadFromS3, deleteFromS3 } = require('../services/s3Service');
const { maskSensitiveText, maskStructuredData } = require('../services/securityService');
const StorageService = require('../services/storageService');
const docFields = require('../services/documentFields');
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

// Stores one plain (Security V1) document and starts reading it. Used by the app upload and by the
// WhatsApp assistant, so a file sent in either place goes through exactly the same steps.
async function savePlainDocument({ userId, buffer, originalName, mimeType, documentType, skipOcr = false }) {
  const uploadResult = await StorageService.uploadFile(buffer, originalName, mimeType, userId, false);

  const document = await Document.create({
    userId,
    filename: uploadResult.filename || uploadResult.s3Key,
    originalName,
    filePath: uploadResult.filePath,
    fileSize: uploadResult.fileSize,
    mimeType,
    documentType: documentType || 'other',
    ocrStatus: skipOcr ? 'skipped' : 'pending',
    storageType: uploadResult.storageType,
    s3Key: uploadResult.s3Key || null,
    s3Location: uploadResult.s3Location || null,
    securityVersion: 1,
    encryptionVersion: 0
  });

  // Fetch the file from wherever this file was actually stored.
  if (!skipOcr) processOCR(document._id, uploadResult.filePath, userId, uploadResult.storageType === 's3');
  return document;
}

exports.savePlainDocument = savePlainDocument;
exports.PLAIN_UPLOAD_TYPES = ['image/jpeg', 'image/png', 'application/pdf'];

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

    const useGridFS = (flags.GRIDFS_ENABLED || isR2Configured()) && user.securityVersion === 2 && isV2Envelope;

    // Guard rails:
    // 1. If V1 user tries to upload a V2 envelope -> reject
    if (isV2Envelope && user.securityVersion !== 2) {
      return res.status(403).json({
        success: false,
        message: 'V1 users are not allowed to upload encrypted V2 documents.'
      });
    }
    // 2. If V2 envelope is submitted but GRIDFS_ENABLED is false -> reject
    if (isV2Envelope && !flags.GRIDFS_ENABLED && !isR2Configured()) {
      return res.status(403).json({
        success: false,
        message: 'Secure GridFS storage is currently disabled.'
      });
    }

    if (useGridFS) {
      // Opaque encrypted upload path (R2 when configured, otherwise GridFS)
      const stored = await StorageService.uploadEncrypted(fileBuffer, header.mimeType, req.userId);

      const document = new Document({
        userId: req.userId,
        filename: 'Encrypted File', // Mask original filename
        originalName: 'encrypted_file', // Mask original filename
        filePath: stored.filePath,
        fileSize: fileBuffer.length,
        mimeType: header.mimeType,
        documentType: documentType || 'other',
        ocrStatus: 'skipped', // Skip server-side OCR
        storageType: stored.storageType,
        gridfsId: stored.gridfsId,
        s3Key: stored.s3Key,
        securityVersion: 2,
        encryptionVersion: 1
      });

      try {
        await document.save();
      } catch (dbErr) {
        console.log('MongoDB save failed, removing the stored encrypted file');
        await StorageService.discardEncrypted(stored).catch(console.error);
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

    const document = await savePlainDocument({
      userId: req.userId,
      buffer: fileBuffer,
      originalName: req.file.originalname,
      mimeType: req.file.mimetype,
      documentType,
    });

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

    // Store the ciphertext (R2 when configured, otherwise GridFS)
    const stored = await StorageService.uploadEncrypted(fileBuffer, header.mimeType, req.userId);

    // Save V2 Document record
    const document = new Document({
      userId: req.userId,
      filename: 'Encrypted File',
      originalName: 'encrypted_file',
      filePath: stored.filePath,
      fileSize: fileBuffer.length,
      mimeType: header.mimeType,
      documentType: req.body.documentType || 'other',
      ocrStatus: 'skipped', // Skip server-side OCR
      storageType: stored.storageType,
      gridfsId: stored.gridfsId,
      s3Key: stored.s3Key,
      securityVersion: 2,
      encryptionVersion: 1
    });

    try {
      await document.save();
    } catch (dbErr) {
      console.error('MongoDB save failed, removing the stored encrypted file');
      await StorageService.discardEncrypted(stored).catch(console.error);
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

    const { text: extractedText, items: layoutItems } = await ocrService.extractTextAndItems(filePath);
    const owner = await User.findById(userId);
    const structuredData = await ocrService.extractWithAI(extractedText, ocrService.parseStructuredData(extractedText), require('../services/aiService'), owner);

    if (structuredData.address) {
      const formAnalyzerService = require('../services/formAnalyzerService');
      const addressComponents = formAnalyzerService.parseAddress(structuredData.address);
      Object.assign(structuredData, addressComponents);
    }

    // Whatever else the document prints (vehicle class, roll number, marks, account number...) is read too, using the
    // page layout, and saved beside the usual fields in one clean shape. The profile below only takes the usual ones.
    const TYPE_NAMES = { aadhaar: 'Aadhaar card', pan: 'PAN card', passport: 'Passport', license: 'Driving licence', voter: 'Voter ID' };
    const named = await Document.findById(documentId).select('originalName').lean();
    const dynamic = await docFields.extractFields({
      text: extractedText,
      items: layoutItems,
      known: structuredData,
      aiService: require('../services/aiService'),
      user: owner,
      typeLabel: TYPE_NAMES[structuredData.documentType] || '',
      fileName: named?.originalName || '',
    }).catch((error) => { console.warn('Reading the other fields failed:', error.message); return { fields: {}, documentTitle: '' }; });
    // The AI reviews the whole record against the document's own text before it is saved (never for encrypted accounts).
    const assembled = docFields.assembleStructured({ known: structuredData, fields: dynamic.fields, documentTitle: dynamic.documentTitle });
    const reviewed = await docFields.reviewWithAI({ text: extractedText, record: assembled, aiService: require('../services/aiService'), user: owner }).catch(() => ({ record: assembled }));
    const stored = reviewed.record;

    await Document.findByIdAndUpdate(documentId, {
      extractedText,
      structuredData: stored,
      fieldsExtractedAt: new Date(),
      ...(['aadhaar', 'pan', 'passport', 'license'].includes(structuredData.documentType) ? { documentType: structuredData.documentType } : {}),
      ocrStatus: 'completed',
    });

    const user = await User.findById(userId);
    // The profile (used to fill forms) takes the usual fields only, never one document's own extras like a roll number.
    const { documentType: _kind, ...profileFields } = docFields.assembleStructured({ known: structuredData, fields: Object.fromEntries(Object.entries(dynamic.fields).filter(([k]) => docFields.KNOWN_KEYS.includes(k))) });
    delete profileFields.documentTitle;
    user.extractedData = {
      ...(user.extractedData || {}),
      ...profileFields,
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

    if (document.storageType === 'gridfs' || document.storageType === 'r2') {
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
    const { encryptedText, encryptedStructuredData } = req.body;
    const user = await User.findById(req.userId);
    const isV2 = user && user.securityVersion === 2;

    // Corrections are flat text fields only: anything else is dropped, so a bad request cannot store objects.
    let structuredData = req.body.structuredData;
    if (structuredData !== undefined) {
      if (!structuredData || typeof structuredData !== 'object' || Array.isArray(structuredData)) {
        return res.status(400).json({ success: false, message: 'structuredData must be an object' });
      }
      structuredData = Object.fromEntries(
        Object.entries(structuredData)
          .filter(([key, value]) => /^[A-Za-z][A-Za-z0-9]{0,39}$/.test(key) && ['string', 'number'].includes(typeof value))
          .map(([key, value]) => [key, String(value).trim().slice(0, 500)])
      );
    }

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
    if (document.storageType === 'gridfs' || document.storageType === 'r2') {
      await StorageService.deleteFile(document).catch((err) =>
        console.error('Encrypted file delete error (non-fatal):', err.message)
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
