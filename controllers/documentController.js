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
const documentReader = require('../services/documentReader');
const { buildPreview, makeThumbnail } = require('../services/documentPreview');
const docKind = require('../services/whatsappDocKind');
const TOP_LEVEL_TYPES = new Set(['aadhaar', 'pan', 'passport', 'license']);
const { flags } = require('../config/featureFlags');

// The usual sensitive fields are masked by name; every other value (the AI's one-line summary, an enrolment or account number ...)
// is scanned for ID-shaped numbers, so no full number leaks through a field the app does not know by name.
const maskListData = (data) => {
  const masked = maskStructuredData(data);
  for (const [key, value] of Object.entries(masked)) {
    if (typeof value === 'string' && !docFields.KNOWN_KEYS.includes(key)) masked[key] = maskSensitiveText(value);
  }
  return masked;
};

const serializeDocument = (document, { reveal = false } = {}) => ({
  ...(document.securityVersion === 2 ? {} : { thumbnail: document.thumbnail || '', preview: buildPreview(document, { reveal }) }),
  id: document._id,
  originalName: document.originalName,
  documentType: document.documentType,
  fileSize: document.fileSize,
  mimeType: document.mimeType,
  ocrStatus: document.ocrStatus,
  storageType: document.storageType,
  uploadedAt: document.uploadedAt,
  structuredData: reveal
    ? docFields.cleanKnown(document.structuredData || {})
    : maskListData(docFields.cleanKnown(document.structuredData || {})),
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
async function savePlainDocument({ userId, buffer, originalName, mimeType, documentType, skipOcr = false, migratedFrom = null }) {
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
    encryptionVersion: 0,
    ...(migratedFrom ? { migratedFrom } : {})
  });

  // Fetch the file from wherever this file was actually stored.
  if (!skipOcr) processOCR(document._id, uploadResult.filePath, userId, uploadResult.storageType === 's3');
  return document;
}

exports.savePlainDocument = savePlainDocument;

// Reads an already stored standard document again with the AI reader (used once for documents saved by the older reader). The
// member's profile is left as it is, so an old document cannot overwrite newer details.
exports.reprocessDocument = async (given) => {
  const document = await Document.findById(given._id || given);
  if (!document || document.securityVersion === 2) return;
  const buffer = await StorageService.downloadFile(document);
  const temp = path.join(os.tmpdir(), `reread-${Date.now()}-${path.basename(document.originalName || 'file')}`);
  await fs.writeFile(temp, buffer);
  try {
    await processOCR(document._id, temp, document.userId, false, { updateProfile: false, requireAi: true });
  } finally {
    await fs.unlink(temp).catch(() => {});
  }
};
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

async function processOCR(documentId, filePathOrKey, userId, useS3 = false, { updateProfile = true, requireAi = false } = {}) {
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

    const owner = await User.findById(userId);
    const aiService = require('../services/aiService');
    const named = await Document.findById(documentId).select('originalName mimeType migratedFrom').lean();

    // The AI model reads the file itself (the picture, or the PDF pages) and returns its kind, the holder's details and every
    // labelled item. No OCR is involved. Only if the AI cannot be used at all does the older OCR-based reading below run, so an
    // upload is never lost.
    const fileBuffer = await fs.readFile(filePath);
    // A copy made while moving off Security V2 is read for the owner as a standard document (they asked for exactly that).
    const readAs = named?.migratedFrom ? { _id: owner._id, securityVersion: 1 } : owner;
    const read = await documentReader.read({ buffer: fileBuffer, mimeType: named?.mimeType, fileName: named?.originalName, user: readAs });
    // A re-read of an older document only goes ahead if the AI could read it: otherwise the earlier data stays untouched.
    if (!read && requireAi) {
      await Document.findByIdAndUpdate(documentId, { ocrStatus: 'completed' });
      return;
    }
    let extractedText = '';
    let layoutItems = [];
    if (!read) {
      ({ text: extractedText, items: layoutItems } = await ocrService.extractTextAndItems(filePath));
    }

    let structuredData;
    let dynamic;
    let stored;
    if (read) {
      structuredData = { ...read.known };
      if (read.documentType !== 'other') structuredData.documentType = read.documentType;
      dynamic = { fields: read.fields, documentTitle: read.documentTitle };
      stored = docFields.assembleStructured({ known: structuredData, fields: dynamic.fields, documentTitle: dynamic.documentTitle, documentSummary: read.documentSummary });
      // The text kept with the document (for search and "text found in the document") is the saved record, written out.
      extractedText = [stored.documentTitle, stored.documentSummary, ...Object.entries(stored)
        .filter(([k]) => !docFields.HIDDEN_KEYS.has(k) && !docFields.ALIAS_KEYS.has(k))
        .map(([k, v]) => `${docFields.labelOf(k)}: ${v}`)].filter(Boolean).join('\n');
    } else {
      structuredData = await ocrService.extractWithAI(extractedText, ocrService.parseStructuredData(extractedText), aiService, owner);
      // Whatever else the document prints (vehicle class, roll number, marks, account number...) is read too, using the
      // page layout, and saved beside the usual fields in one clean shape. The profile below only takes the usual ones.
      const TYPE_NAMES = { aadhaar: 'Aadhaar card', pan: 'PAN card', passport: 'Passport', license: 'Driving licence', voter: 'Voter ID' };
      dynamic = await docFields.extractFields({
        text: extractedText,
        items: layoutItems,
        known: structuredData,
        aiService,
        user: owner,
        typeLabel: TYPE_NAMES[structuredData.documentType] || '',
        fileName: named?.originalName || '',
      }).catch((error) => { console.warn('Reading the other fields failed:', error.message); return { fields: {}, documentTitle: '' }; });
      const assembled = docFields.assembleStructured({ known: structuredData, fields: dynamic.fields, documentTitle: dynamic.documentTitle });
      const reviewed = await docFields.reviewWithAI({ text: extractedText, record: assembled, aiService, user: owner }).catch(() => ({ record: assembled }));
      stored = reviewed.record;
    }

    if (structuredData.address) {
      const formAnalyzerService = require('../services/formAnalyzerService');
      const addressComponents = formAnalyzerService.parseAddress(structuredData.address);
      // Only the pieces the app really uses; the many alias spellings of the same pieces are not stored.
      const pieces = Object.fromEntries(['city', 'district'].filter((k) => addressComponents[k]).map((k) => [k, addressComponents[k]]));
      Object.assign(structuredData, pieces);
      Object.assign(stored, Object.fromEntries(Object.entries(pieces).filter(([k]) => !(k in stored))));
    }

    // The kind of document, kept on the document itself: it is what the app counts for "Your ID cards". The reader's answer
    // wins; when it said nothing, the scored guess from the text (which copes with noisy photos) is used if it is sure.
    const kindFromText = docKind.kindFromOcrText(extractedText);
    const finalKind = ['aadhaar', 'pan', 'passport', 'license'].includes(structuredData.documentType) ? structuredData.documentType
      : (!read && kindFromText && TOP_LEVEL_TYPES.has(kindFromText.key) ? kindFromText.key : null);
    if (finalKind && !stored.documentType) stored.documentType = finalKind;

    await Document.findByIdAndUpdate(documentId, {
      extractedText,
      structuredData: stored,
      fieldsExtractedAt: new Date(),
      // When the AI read it, its answer is the kind, including "not an ID card" (so a stale label from an older reader is replaced).
      ...(finalKind ? { documentType: finalKind } : (read ? { documentType: 'other' } : {})),
      thumbnail: await makeThumbnail(fileBuffer, named?.mimeType),
      ...(read ? { aiReadAt: new Date() } : {}),
      ocrStatus: 'completed',
    });

    if (updateProfile && !named?.migratedFrom) {
    const user = await User.findById(userId);
    // The profile (used to fill forms) takes the usual fields only, never one document's own extras like a roll number.
    const { documentType: _kind, ...profileFields } = docFields.assembleStructured({ known: structuredData, fields: Object.fromEntries(Object.entries(dynamic.fields).filter(([k]) => docFields.KNOWN_KEYS.includes(k))) });
    delete profileFields.documentTitle;
    user.extractedData = {
      ...(user.extractedData || {}),
      ...profileFields,
    };
    await user.save();
    }

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
      // A usual field has to look like what it holds, so a mistyped correction cannot put a paragraph in a name or a bad Aadhaar number in the profile.
      const KIND = { fullName: 'name', fatherName: "father's name", dateOfBirth: 'date of birth (DD/MM/YYYY)', gender: 'gender', aadhaarNumber: 'Aadhaar number (12 digits)', panNumber: 'PAN number (like ABCDE1234F)', passportNumber: 'passport number', drivingLicenseNumber: 'licence number', pincode: 'PIN code (6 digits)', phone: 'phone number (10 digits)', email: 'email address', state: 'state', address: 'address' };
      const bad = Object.entries(structuredData).find(([key, value]) => docFields.KNOWN_KEYS.includes(key) && value && !docFields.valueFitsKey(key, value));
      if (bad) return res.status(400).json({ success: false, message: `That is not a valid ${KIND[bad[0]] || bad[0]}. Check it against your document.` });
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
      if (doc.structuredData) Object.assign(merged, docFields.cleanKnown(doc.structuredData));
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
