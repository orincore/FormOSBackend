const User = require('../models/User');
const formAnalyzerService = require('../services/formAnalyzerService');
const { isS3Configured, downloadFromS3 } = require('../services/s3Service');
const fs = require('fs').promises;
const path = require('path');
const os = require('os');

/**
 * Analyze form - handles both file upload and mock fields
 */
exports.analyzeForm = async (req, res) => {
  try {
    console.log('=== Form Analyzer Request ===');
    console.log('Has file:', !!req.file);
    console.log('Has mockFields:', !!req.body.mockFields);
    
    // Get user data
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const userData = user.extractedData || {};
    console.log('User data available:', Object.keys(userData));
    
    let result;

    // Check if file was uploaded
    if (req.file) {
      console.log('Processing file upload:', req.file.originalname);
      console.log('File details:', {
        path: req.file.path,
        key: req.file.key,
        size: req.file.size,
        mimetype: req.file.mimetype
      });
      
      const useS3 = isS3Configured() && req.file.key; // Only use S3 if key exists
      let filePath = req.file.path;
      let tempFilePath = null;

      try {
        // If using S3, download file temporarily to os.tmpdir()
        if (useS3) {
          console.log('Using S3 storage, downloading file...');
          const fileBuffer = await downloadFromS3(req.file.key);
          tempFilePath = path.join(os.tmpdir(), `temp-${Date.now()}-${path.basename(req.file.key)}`);
          await fs.writeFile(tempFilePath, fileBuffer);
          filePath = tempFilePath;
        } else {
          console.log('Using local storage:', filePath);
          // Verify file exists
          try {
            await fs.access(filePath);
          } catch (err) {
            throw new Error(`File not found at path: ${filePath}`);
          }
        }

        // Analyze uploaded form
        console.log('Starting form analysis...');
        result = await formAnalyzerService.analyzeUploadedForm(filePath, userData);
        console.log('Analysis complete. Fields found:', result.totalFields);

        // Clean up temp file
        if (tempFilePath) {
          await fs.unlink(tempFilePath).catch(console.error);
        }
        // Only delete local file if not using S3
        if (!useS3 && req.file.path) {
          await fs.unlink(req.file.path).catch(err => {
            console.error('Error deleting file:', err);
          });
        }
      } catch (error) {
        console.error('File processing error:', error);
        // Clean up on error
        if (tempFilePath) {
          await fs.unlink(tempFilePath).catch(console.error);
        }
        if (!useS3 && req.file.path) {
          await fs.unlink(req.file.path).catch(console.error);
        }
        throw error;
      }
    } 
    // Check if mock fields were provided
    else if (req.body.mockFields) {
      console.log('Processing mock fields');
      const mockFields = Array.isArray(req.body.mockFields) 
        ? req.body.mockFields 
        : JSON.parse(req.body.mockFields);
      
      console.log('Mock fields:', mockFields);
      result = formAnalyzerService.analyzeMockForm(mockFields, userData);
      console.log('Analysis complete. Fields analyzed:', result.totalFields);
    } 
    else {
      return res.status(400).json({
        success: false,
        message: 'Please provide either a form file or mock fields'
      });
    }

    // Generate AI context for RAG integration
    const aiContext = formAnalyzerService.generateAIContext(result);

    console.log('=== Analysis Success ===');
    res.json({
      success: true,
      message: 'Form analyzed successfully',
      ...result,
      aiContext
    });
  } catch (error) {
    console.error('=== Form Analysis Error ===');
    console.error('Error:', error.message);
    console.error('Stack:', error.stack);
    res.status(500).json({
      success: false,
      message: 'Error analyzing form',
      error: error.message,
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
};

/**
 * Get user's stored data for preview
 */
exports.getUserData = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const Document = require('../models/Document');
    const docCount = await Document.countDocuments({ userId: req.userId });

    const userData = user.extractedData || {};
    
    res.json({
      success: true,
      securityVersion: user.securityVersion || 1,
      encryptedProfile: user.encryptedProfile || null,
      userSalt: user.userSalt || null,
      userData: {
        fullName: userData.fullName || user.name || null,
        dateOfBirth: userData.dateOfBirth || null,
        address: userData.address || null,
        phone: userData.phone || user.phone || null,
        email: userData.email || user.email || null,
        hasAadhaar: !!userData.aadhaarNumber,
        hasPAN: !!userData.panNumber,
        customFields: userData.customFields || {},
        documentsCount: docCount
      }
    });
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching user data'
    });
  }
};

/**
 * Prepare autofill data from analysis result
 */
exports.prepareAutofill = async (req, res) => {
  try {
    const { analysisResult } = req.body;
    
    if (!analysisResult || !analysisResult.autofillData) {
      return res.status(400).json({
        success: false,
        message: 'Invalid analysis result'
      });
    }

    const { autofillData } = analysisResult;

    if (!autofillData.canAutofill) {
      return res.json({
        success: true,
        canAutofill: false,
        message: 'No fields available for autofill',
        fieldCount: 0
      });
    }

    // Format for autofill system
    const autofillPayload = {
      fields: autofillData.fields.reduce((acc, field) => {
        acc[field.normalizedName] = {
          value: field.value,
          confidence: field.confidence,
          source: field.mappedFrom
        };
        return acc;
      }, {})
    };

    res.json({
      success: true,
      canAutofill: true,
      fieldCount: autofillData.fieldCount,
      message: `${autofillData.fieldCount} field(s) ready for autofill`,
      autofillPayload
    });
  } catch (error) {
    console.error('Error preparing autofill:', error);
    res.status(500).json({
      success: false,
      message: 'Error preparing autofill data'
    });
  }
};

/**
 * Update user field manually
 */
exports.updateField = async (req, res) => {
  try {
    const { fieldName, value } = req.body;
    
    if (!fieldName || value === undefined) {
      return res.status(400).json({
        success: false,
        message: 'Field name and value are required'
      });
    }

    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Initialize extractedData if it doesn't exist
    if (!user.extractedData) {
      user.extractedData = {};
    }

    // Map normalized field names to actual user data fields
    const fieldMapping = {
      'name': 'fullName',
      'full_name': 'fullName',
      'fullname': 'fullName',
      'first_name': 'firstName',
      'firstname': 'firstName',
      'last_name': 'lastName',
      'lastname': 'lastName',
      'middle_name': 'middleName',
      'middlename': 'middleName',
      'date_of_birth': 'dateOfBirth',
      'dob': 'dateOfBirth',
      'address': 'address',
      'street': 'street',
      'city': 'city',
      'state': 'state',
      'zip': 'zip',
      'zipcode': 'zip',
      'postal_code': 'zip',
      'pin': 'zip',
      'pincode': 'zip',
      'phone': 'phone',
      'mobile': 'phone',
      'email': 'email',
      'aadhaar': 'aadhaarNumber',
      'aadhaar_number': 'aadhaarNumber',
      'pan': 'panNumber',
      'pan_number': 'panNumber'
    };

    const actualFieldName = fieldMapping[fieldName.toLowerCase()] || fieldName;
    
    // Update the field
    user.extractedData[actualFieldName] = value;
    
    // If updating address components, also update the full address
    if (['street', 'city', 'state', 'zip'].includes(actualFieldName)) {
      const addressParts = [
        user.extractedData.street,
        user.extractedData.city,
        user.extractedData.state,
        user.extractedData.zip
      ].filter(Boolean);
      
      if (addressParts.length > 0) {
        user.extractedData.address = addressParts.join(', ');
      }
    }
    
    // If updating name components, also update full name
    if (['firstName', 'middleName', 'lastName'].includes(actualFieldName)) {
      const nameParts = [
        user.extractedData.firstName,
        user.extractedData.middleName,
        user.extractedData.lastName
      ].filter(Boolean);
      
      if (nameParts.length > 0) {
        user.extractedData.fullName = nameParts.join(' ');
      }
    }

    await user.save();

    res.json({
      success: true,
      message: 'Field updated successfully',
      updatedField: actualFieldName,
      value: value
    });
  } catch (error) {
    console.error('Error updating field:', error);
    res.status(500).json({
      success: false,
      message: 'Error updating field'
    });
  }
};

const validateLabels = (labels) => {
  if (!Array.isArray(labels)) {
    throw new Error('Labels must be an array of strings');
  }

  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/;
  // Phone numbers: check for 10-12 digits optionally prefixed with +
  const phoneRegex = /\+?\d{10,12}/;
  // Aadhaar numbers: 12 digits (often spaced in groups of 4)
  const aadhaarRegex = /\d{4}\s?\d{4}\s?\d{4}/;
  // PAN numbers: 5 letters, 4 digits, 1 letter
  const panRegex = /[A-Z]{5}\d{4}[A-Z]/i;
  // Passport numbers: 1 letter, 7 digits
  const passportRegex = /[A-Z]\d{7}/i;
  // Long identifier tokens: e.g. 15+ alphanumeric chars
  const longTokenRegex = /[a-zA-Z0-9_-]{15,}/;

  for (const label of labels) {
    if (typeof label !== 'string') {
      throw new Error('Each label must be a string');
    }
    if (label.length > 50) {
      throw new Error(`Label exceeds maximum length of 50 characters: "${label.substring(0, 20)}..."`);
    }
    if (emailRegex.test(label)) {
      throw new Error(`Potential sensitive data detected (email) in label: "${label}"`);
    }
    if (phoneRegex.test(label)) {
      throw new Error(`Potential sensitive data detected (phone) in label: "${label}"`);
    }
    if (aadhaarRegex.test(label)) {
      throw new Error(`Potential sensitive data detected (Aadhaar) in label: "${label}"`);
    }
    if (panRegex.test(label)) {
      throw new Error(`Potential sensitive data detected (PAN) in label: "${label}"`);
    }
    if (passportRegex.test(label)) {
      throw new Error(`Potential sensitive data detected (passport ID) in label: "${label}"`);
    }
    if (longTokenRegex.test(label)) {
      throw new Error(`Potential sensitive data detected (long ID token) in label: "${label}"`);
    }
  }
};

exports.mapStructure = async (req, res) => {
  try {
    const { labels } = req.body;
    
    if (!labels) {
      return res.status(400).json({
        success: false,
        message: 'Missing labels array in request body'
      });
    }

    // Secondary defense validator
    try {
      validateLabels(labels);
    } catch (valErr) {
      return res.status(400).json({
        success: false,
        message: valErr.message
      });
    }

    const aiService = require('../services/aiService');
    if (!aiService.isConfigured()) {
      return res.status(503).json({
        success: false,
        message: 'AI service is not configured'
      });
    }

    const systemPrompt = `You are a schema mapping AI. You map arbitrary document field labels to canonical FormOS profile fields.
Canonical FormOS fields are:
- full_name
- first_name
- last_name
- date_of_birth
- phone
- email
- address
- pan_number
- passport_number
- employee_id
- company
- degree
- joining_date

Map each input label to the closest matching canonical field name. If no match is found, map it to null.
Return the output strictly as a JSON object of key-value pairs where the key is the input label and the value is the mapped canonical field. Do not include any explanations, markdown code blocks, or preamble.`;

    const user = req.user || (req.userId ? await User.findById(req.userId) : null);
    const userPrompt = JSON.stringify(labels);
    const aiResponse = await aiService.chat(systemPrompt, userPrompt, {
      user,
      operation: aiService.AI_OPERATION.SCHEMA_MAPPING
    });

    let mappings = {};
    try {
      const cleanJson = aiResponse.replace(/```json|```/g, '').trim();
      mappings = JSON.parse(cleanJson);
    } catch (parseError) {
      console.error('Failed to parse AI response:', aiResponse);
      return res.status(502).json({
        success: false,
        message: 'Invalid response format from AI mapping service'
      });
    }

    return res.json({
      success: true,
      mappings
    });
  } catch (error) {
    console.error('Map structure error:', error);
    if (error.name === 'AIPolicyViolationError') {
      return res.status(403).json({
        success: false,
        code: error.code,
        message: error.message,
        operation: error.operation,
        securityVersion: error.securityVersion
      });
    }
    return res.status(500).json({
      success: false,
      message: 'Error mapping document structure'
    });
  }
};
