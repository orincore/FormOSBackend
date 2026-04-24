const fs = require('fs').promises;
const path = require('path');
const os = require('os');
const Document = require('../models/Document');
const User = require('../models/User');
const ocrService = require('../services/ocrService');
const { isS3Configured, downloadFromS3, deleteFromS3 } = require('../services/s3Service');
const { maskSensitiveText, maskStructuredData } = require('../services/securityService');

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
    const useS3 = isS3Configured();

    const document = await Document.create({
      userId: req.userId,
      filename: req.file.filename || req.file.key,
      originalName: req.file.originalname,
      filePath: useS3 ? req.file.key : req.file.path,
      fileSize: req.file.size,
      mimeType: req.file.mimetype,
      documentType: documentType || 'other',
      ocrStatus: 'pending',
      storageType: useS3 ? 's3' : 'local',
      s3Key: useS3 ? req.file.key : null,
      s3Location: useS3 ? req.file.location : null,
    });

    processOCR(document._id, useS3 ? req.file.key : req.file.path, req.userId, useS3);

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
    const { structuredData } = req.body;

    const document = await Document.findOneAndUpdate(
      { _id: req.params.id, userId: req.userId },
      { structuredData },
      { new: true }
    );

    if (!document) {
      return res.status(404).json({
        success: false,
        message: 'Document not found',
      });
    }

    const user = await User.findById(req.userId);
    user.extractedData = {
      ...(user.extractedData || {}),
      ...structuredData,
    };
    await user.save();

    return res.json({
      success: true,
      message: 'Data updated successfully',
      document: serializeDocument(document, { reveal: true }),
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

    // Delete from S3 or local filesystem
    if (document.storageType === 's3' && document.s3Key) {
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
