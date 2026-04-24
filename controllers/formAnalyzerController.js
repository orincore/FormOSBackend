const User = require('../models/User');
const formAnalyzerService = require('../services/formAnalyzerService');
const { isS3Configured, downloadFromS3 } = require('../services/s3Service');
const fs = require('fs').promises;
const path = require('path');

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
        // If using S3, download file temporarily
        if (useS3) {
          console.log('Using S3 storage, downloading file...');
          const fileBuffer = await downloadFromS3(req.file.key);
          const tempDir = process.env.UPLOAD_DIR || './uploads';
          tempFilePath = path.join(tempDir, `temp-${Date.now()}-${path.basename(req.file.key)}`);
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

    const userData = user.extractedData || {};
    
    res.json({
      success: true,
      userData: {
        fullName: userData.fullName || null,
        dateOfBirth: userData.dateOfBirth || null,
        address: userData.address || null,
        phone: userData.phone || null,
        email: userData.email || null,
        hasAadhaar: !!userData.aadhaarNumber,
        hasPAN: !!userData.panNumber,
        customFields: userData.customFields || {}
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
