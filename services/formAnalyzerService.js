const ocrService = require('./ocrService');

class FormAnalyzerService {
  constructor() {
    // Field mapping rules with match types
    this.fieldMappings = {
      // Name variations - IMPROVED with smart parsing
      'name': { userField: 'fullName', type: 'exact', confidence: 1.0 },
      'full_name': { userField: 'fullName', type: 'exact', confidence: 1.0 },
      'fullname': { userField: 'fullName', type: 'exact', confidence: 1.0 },
      
      // First name - maps to parsed firstName
      'first_name': { userField: 'firstName', type: 'exact', confidence: 1.0 },
      'firstname': { userField: 'firstName', type: 'exact', confidence: 1.0 },
      'given_name': { userField: 'firstName', type: 'synonym', confidence: 0.95 },
      
      // Last name - maps to parsed lastName
      'last_name': { userField: 'lastName', type: 'exact', confidence: 1.0 },
      'lastname': { userField: 'lastName', type: 'exact', confidence: 1.0 },
      'surname': { userField: 'lastName', type: 'synonym', confidence: 0.95 },
      'family_name': { userField: 'lastName', type: 'synonym', confidence: 0.95 },
      
      // Middle name - maps to parsed middleName
      'middle_name': { userField: 'middleName', type: 'exact', confidence: 0.9 },
      'middlename': { userField: 'middleName', type: 'exact', confidence: 0.9 },
      
      // Date of birth variations
      'date_of_birth': { userField: 'dateOfBirth', type: 'exact', confidence: 1.0 },
      'dob': { userField: 'dateOfBirth', type: 'synonym', confidence: 0.9 },
      'birth_date': { userField: 'dateOfBirth', type: 'synonym', confidence: 0.9 },
      'birthdate': { userField: 'dateOfBirth', type: 'synonym', confidence: 0.9 },
      'date_of_birth_ddmmyyyy': { userField: 'dateOfBirth', type: 'exact', confidence: 1.0 },
      
      // Address variations - IMPROVED with smart parsing
      'address': { userField: 'address', type: 'exact', confidence: 1.0 },
      'full_address': { userField: 'address', type: 'exact', confidence: 1.0 },
      'complete_address': { userField: 'address', type: 'exact', confidence: 1.0 },
      
      // Street - maps to parsed street
      'street': { userField: 'street', type: 'exact', confidence: 0.95 },
      'street_address': { userField: 'streetAddress', type: 'exact', confidence: 0.95 },
      'address_line_1': { userField: 'addressLine1', type: 'exact', confidence: 0.95 },
      'address_line1': { userField: 'addressLine1', type: 'exact', confidence: 0.95 },
      'line1': { userField: 'addressLine1', type: 'synonym', confidence: 0.9 },
      
      // Address Line 2
      'address_line_2': { userField: 'addressLine2', type: 'exact', confidence: 0.9 },
      'address_line2': { userField: 'addressLine2', type: 'exact', confidence: 0.9 },
      'line2': { userField: 'addressLine2', type: 'synonym', confidence: 0.85 },
      
      // City - maps to parsed city
      'city': { userField: 'city', type: 'exact', confidence: 0.95 },
      'town': { userField: 'city', type: 'synonym', confidence: 0.9 },
      
      // State - maps to parsed state
      'state': { userField: 'state', type: 'exact', confidence: 0.95 },
      'province': { userField: 'state', type: 'synonym', confidence: 0.9 },
      
      // ZIP/Postal Code - maps to parsed zip
      'zip': { userField: 'zip', type: 'exact', confidence: 0.95 },
      'zipcode': { userField: 'zipCode', type: 'exact', confidence: 0.95 },
      'zip_code': { userField: 'zipCode', type: 'exact', confidence: 0.95 },
      'postal_code': { userField: 'postalCode', type: 'exact', confidence: 0.95 },
      'postcode': { userField: 'postalCode', type: 'exact', confidence: 0.95 },
      'pin': { userField: 'zip', type: 'synonym', confidence: 0.9 },
      'pincode': { userField: 'zip', type: 'synonym', confidence: 0.9 },
      'pin_code': { userField: 'zip', type: 'synonym', confidence: 0.9 },
      
      // Other address variations (fallback to full address)
      'home_address': { userField: 'address', type: 'synonym', confidence: 0.9 },
      'residential_address': { userField: 'address', type: 'synonym', confidence: 0.9 },
      'mailing_address': { userField: 'address', type: 'synonym', confidence: 0.85 },
      
      // Phone variations
      'phone': { userField: 'phone', type: 'exact', confidence: 1.0 },
      'mobile': { userField: 'phone', type: 'synonym', confidence: 0.95 },
      'telephone': { userField: 'phone', type: 'synonym', confidence: 0.9 },
      'phone_number': { userField: 'phone', type: 'exact', confidence: 1.0 },
      'mobile_number': { userField: 'phone', type: 'synonym', confidence: 0.95 },
      'cell': { userField: 'phone', type: 'synonym', confidence: 0.9 },
      'cell_phone': { userField: 'phone', type: 'synonym', confidence: 0.9 },
      'contact_number': { userField: 'phone', type: 'synonym', confidence: 0.9 },
      
      // Email variations
      'email': { userField: 'email', type: 'exact', confidence: 1.0 },
      'email_address': { userField: 'email', type: 'exact', confidence: 1.0 },
      'e_mail': { userField: 'email', type: 'synonym', confidence: 0.95 },
      'mail': { userField: 'email', type: 'synonym', confidence: 0.85 },
      
      // Document numbers
      'aadhaar': { userField: 'aadhaarNumber', type: 'exact', confidence: 1.0 },
      'aadhaar_number': { userField: 'aadhaarNumber', type: 'exact', confidence: 1.0 },
      'aadhar': { userField: 'aadhaarNumber', type: 'synonym', confidence: 0.95 },
      'pan': { userField: 'panNumber', type: 'exact', confidence: 1.0 },
      'pan_number': { userField: 'panNumber', type: 'exact', confidence: 1.0 },
      'pan_card': { userField: 'panNumber', type: 'synonym', confidence: 0.95 },
    };

    // Confidence thresholds
    this.CONFIDENCE_THRESHOLDS = {
      HIGH: 0.8,
      MEDIUM: 0.6,
      LOW: 0.4,
      AUTOFILL_MIN: 0.7
    };
  }

  /**
   * Extract form fields from text or use provided mock fields
   */
  extractFormFields(text) {
    const fields = new Set();
    
    // Handle empty or invalid text
    if (!text || text.trim().length === 0) {
      console.warn('No text provided for field extraction');
      return [];
    }
    
    // Common form field patterns
    const patterns = [
      /(?:Full\s+)?Name/i,
      /First\s+Name/i,
      /Last\s+Name/i,
      /Surname/i,
      /Date\s+of\s+Birth|DOB/i,
      /Birth\s+Date/i,
      /Address/i,
      /Street/i,
      /City/i,
      /State/i,
      /ZIP|Postal\s+Code/i,
      /Email/i,
      /Phone|Mobile|Telephone/i,
      /Aadhaar/i,
      /PAN/i,
      /Gender/i,
      /Nationality/i,
      /Occupation/i,
      /Company/i,
      /Emergency\s+Contact/i
    ];

    patterns.forEach(pattern => {
      const match = text.match(pattern);
      if (match) {
        fields.add(this.normalizeFieldName(match[0]));
      }
    });

    const extractedFields = Array.from(fields);
    console.log(`Extracted ${extractedFields.length} fields from text`);
    return extractedFields;
  }

  /**
   * Normalize field names for consistent matching
   */
  normalizeFieldName(fieldName) {
    return fieldName
      .toLowerCase()
      .trim()
      .replace(/\s+/g, '_')
      .replace(/[^a-z0-9_]/g, '');
  }

  /**
   * Parse address into components
   */
  parseAddress(address) {
    if (!address || typeof address !== 'string') {
      return {};
    }

    const parsed = {};
    const addressStr = address.trim();
    
    // Split by common delimiters (comma, newline, semicolon, hyphen)
    const parts = addressStr.split(/[,\n;-]+/).map(p => p.trim()).filter(p => p);
    
    if (parts.length === 0) return {};

    // Common patterns for Indian addresses:
    // "Street, Area, City, State PIN"
    // "Building, Street, City - PIN"
    // "Street, City, State, PIN"
    // Aadhaar format: "House/Street, Area, City, State - PIN"
    
    // Try to extract ZIP/PIN code (usually 5-6 digits, may have spaces)
    const zipMatch = addressStr.match(/\b(\d{3}\s?\d{3}|\d{5,6})\b/);
    if (zipMatch) {
      const zip = zipMatch[1].replace(/\s/g, '');
      parsed.zip = zip;
      parsed.zipCode = zip;
      parsed.postalCode = zip;
    }

    // Try to extract state (common Indian states or US states)
    // Enhanced patterns to catch more variations
    const statePatterns = [
      // Full state names (case insensitive)
      /\b(Maharashtra|Gujarat|Karnataka|Tamil\s*Nadu|Delhi|Rajasthan|Uttar\s*Pradesh|Madhya\s*Pradesh|West\s*Bengal|Punjab|Haryana|Bihar|Odisha|Kerala|Assam|Jharkhand|Chhattisgarh|Goa|Uttarakhand|Himachal\s*Pradesh|Tripura|Meghalaya|Manipur|Nagaland|Arunachal\s*Pradesh|Mizoram|Sikkim|Telangana|Andhra\s*Pradesh)\b/i,
      // State abbreviations
      /\b(MH|GJ|KA|TN|DL|RJ|UP|MP|WB|PB|HR|BR|OR|KL|AS|JH|CG|GA|UK|HP|TR|ML|MN|NL|AR|MZ|SK|TS|AP)\b/,
      // US states
      /\b(CA|NY|TX|FL|IL|PA|OH|GA|NC|MI|NJ|VA|WA|AZ|MA|TN|IN|MO|MD|WI|CO|MN|SC|AL|LA|KY|OR|OK|CT|UT|IA|NV|AR|MS|KS|NM|NE|WV|ID|HI|NH|ME|MT|RI|DE|SD|ND|AK|VT|WY)\b/
    ];
    
    for (const pattern of statePatterns) {
      const stateMatch = addressStr.match(pattern);
      if (stateMatch) {
        parsed.state = stateMatch[1].toUpperCase();
        break;
      }
    }

    // Try to extract city (usually before state or with PIN)
    // First try to match common city names
    const commonCities = /\b(Mumbai|Delhi|Bangalore|Bengaluru|Hyderabad|Chennai|Kolkata|Pune|Ahmedabad|Surat|Jaipur|Lucknow|Kanpur|Nagpur|Indore|Thane|Bhopal|Visakhapatnam|Pimpri|Patna|Vadodara|Ghaziabad|Ludhiana|Agra|Nashik|Faridabad|Meerut|Rajkot|Kalyan|Vasai|Varanasi|Srinagar|Aurangabad|Dhanbad|Amritsar|Navi Mumbai|Allahabad|Ranchi|Howrah|Coimbatore|Jabalpur|Gwalior|Vijayawada|Jodhpur|Madurai|Raipur|Kota|Chandigarh|Guwahati|Solapur|Hubli|Mysore|Tiruchirappalli|Bareilly|Aligarh|Moradabad|Jalandhar|Bhubaneswar|Salem|Warangal|Guntur|Bhiwandi|Saharanpur|Gorakhpur|Bikaner|Amravati|Noida|Jamshedpur|Bhilai|Cuttack|Firozabad|Kochi|Nellore|Bhavnagar|Dehradun|Durgapur|Asansol|Rourkela|Nanded|Kolhapur|Ajmer|Akola|Gulbarga|Jamnagar|Ujjain|Loni|Siliguri|Jhansi|Ulhasnagar|Jammu|Sangli|Mangalore|Erode|Belgaum|Ambattur|Tirunelveli|Malegaon|Gaya|Jalgaon|Udaipur|Maheshtala)\b/i;
    const cityMatch = addressStr.match(commonCities);
    if (cityMatch) {
      parsed.city = cityMatch[1];
    } else if (parts.length >= 2) {
      // If no common city found, try to extract from parts
      // Look for capitalized words that might be city names
      let cityFound = false;
      
      for (let i = Math.max(0, parts.length - 3); i < parts.length; i++) {
        const part = parts[i];
        // Remove ZIP code and state from potential city
        let cityClean = part
          .replace(/\b\d{3}\s?\d{3}\b/g, '')
          .replace(/\b\d{5,6}\b/g, '')
          .replace(/\b(MH|GJ|KA|TN|DL|RJ|UP|MP|WB|PB|HR|BR|OR|KL|AS|JH|CG|GA|UK|HP|TR|ML|MN|NL|AR|MZ|SK|TS|AP)\b/gi, '')
          .replace(/\b(Maharashtra|Gujarat|Karnataka|Tamil\s*Nadu|Delhi|Rajasthan|Uttar\s*Pradesh|Madhya\s*Pradesh|West\s*Bengal|Punjab|Haryana|Bihar|Odisha|Kerala|Assam|Jharkhand|Chhattisgarh|Goa|Uttarakhand|Himachal\s*Pradesh|Tripura|Meghalaya|Manipur|Nagaland|Arunachal\s*Pradesh|Mizoram|Sikkim|Telangana|Andhra\s*Pradesh)\b/gi, '')
          .trim();
        
        // City should be at least 3 characters, start with capital letter, and not be a common address keyword
        const addressKeywords = /^(house|flat|plot|building|street|road|lane|area|sector|behind|near|opp|opposite|block|floor|apt|apartment|villa|tower|complex|society|colony|nagar|puram|ganj|pur|bad|garh|office|m\.?s\.?e\.?b)$/i;
        
        if (cityClean && 
            cityClean.length >= 3 && 
            /^[A-Z]/.test(cityClean) &&
            !addressKeywords.test(cityClean)) {
          parsed.city = cityClean;
          cityFound = true;
          break;
        }
      }
    }

    // Street is usually the first part(s)
    if (parts.length >= 1) {
      // Take first 1-2 parts as street (excluding city/state/zip parts)
      const streetParts = parts.slice(0, Math.min(2, Math.max(1, parts.length - 2)));
      if (streetParts.length > 0) {
        parsed.street = streetParts.join(', ');
        parsed.streetAddress = streetParts.join(', ');
      }
    }

    // Full address line 1 (first part)
    if (parts[0]) {
      parsed.addressLine1 = parts[0];
    }

    // Full address line 2 (remaining parts)
    if (parts.length > 1) {
      parsed.addressLine2 = parts.slice(1).join(', ');
    }

    return parsed;
  }

  /**
   * Map user data fields to normalized names
   */
  getUserDataMap(userData) {
    const map = {};
    
    // Store full name
    if (userData.fullName) {
      map.fullName = userData.fullName;
      
      // Smart name parsing - split full name into components
      const nameParts = userData.fullName.trim().split(/\s+/);
      if (nameParts.length >= 2) {
        // First name is the first part
        map.firstName = nameParts[0];
        // Last name is everything after the first part
        map.lastName = nameParts.slice(1).join(' ');
        
        // If there are 3+ parts, middle name is the middle parts
        if (nameParts.length >= 3) {
          map.middleName = nameParts.slice(1, -1).join(' ');
          map.lastName = nameParts[nameParts.length - 1];
        }
      } else if (nameParts.length === 1) {
        // Only one name provided
        map.firstName = nameParts[0];
      }
    }
    
    if (userData.dateOfBirth) map.dateOfBirth = userData.dateOfBirth;
    
    // Store full address and parse components
    if (userData.address) {
      map.address = userData.address;
      
      // Smart address parsing
      const addressComponents = this.parseAddress(userData.address);
      Object.assign(map, addressComponents);
    }
    
    if (userData.phone) map.phone = userData.phone;
    if (userData.email) map.email = userData.email;
    if (userData.aadhaarNumber) map.aadhaarNumber = userData.aadhaarNumber;
    if (userData.panNumber) map.panNumber = userData.panNumber;

    // Add custom fields
    if (userData.customFields) {
      Object.keys(userData.customFields).forEach(key => {
        map[key] = userData.customFields[key];
      });
    }

    return map;
  }

  /**
   * Find best match for a field with confidence scoring
   */
  findFieldMatch(normalizedField, userDataMap) {
    // Try exact mapping first
    if (this.fieldMappings[normalizedField]) {
      const mapping = this.fieldMappings[normalizedField];
      const value = userDataMap[mapping.userField];
      
      if (value) {
        // Determine reason based on type and field
        let reason;
        const isParsedName = ['firstName', 'lastName', 'middleName'].includes(mapping.userField);
        const isParsedAddress = ['street', 'streetAddress', 'city', 'state', 'zip', 'zipCode', 'postalCode', 'addressLine1', 'addressLine2'].includes(mapping.userField);
        
        if (isParsedName) {
          reason = 'exact match (parsed from full name)';
        } else if (isParsedAddress) {
          reason = 'exact match (parsed from address)';
        } else {
          switch (mapping.type) {
            case 'exact':
              reason = 'exact match';
              break;
            case 'synonym':
              reason = 'synonym match (common variation)';
              break;
            case 'partial':
              reason = 'partial match (field component)';
              break;
            default:
              reason = 'fallback mapping';
          }
        }
        
        return {
          matched: true,
          mappedTo: mapping.userField,
          value: value,
          confidence: mapping.confidence,
          reason: reason
        };
      }
    }

    // Try fuzzy matching for unmapped fields
    const fuzzyMatch = this.fuzzyMatch(normalizedField, userDataMap);
    if (fuzzyMatch) {
      return fuzzyMatch;
    }

    // No match found
    return {
      matched: false,
      mappedTo: null,
      value: null,
      confidence: 0,
      reason: 'no match found'
    };
  }

  /**
   * Fuzzy matching for fields not in predefined mappings
   */
  fuzzyMatch(normalizedField, userDataMap) {
    const availableFields = Object.keys(userDataMap);
    
    for (const userField of availableFields) {
      const normalizedUserField = this.normalizeFieldName(userField);
      
      // Check if field contains user field or vice versa
      if (normalizedField.includes(normalizedUserField) || 
          normalizedUserField.includes(normalizedField)) {
        return {
          matched: true,
          mappedTo: userField,
          value: userDataMap[userField],
          confidence: 0.65,
          reason: 'fuzzy match'
        };
      }
    }
    
    return null;
  }

  /**
   * Generate suggestions based on field status
   */
  generateSuggestion(field, matchResult) {
    if (!matchResult.matched) {
      return {
        action: 'upload_or_enter',
        message: 'Upload a document containing this information or enter manually',
        priority: 'high'
      };
    }

    // High confidence - ready to use
    if (matchResult.confidence >= this.CONFIDENCE_THRESHOLDS.HIGH) {
      return {
        action: 'autofill',
        message: 'Ready for autofill - high confidence match',
        priority: 'none'
      };
    }

    // Medium confidence - confirm before use
    if (matchResult.confidence >= this.CONFIDENCE_THRESHOLDS.MEDIUM) {
      return {
        action: 'confirm',
        message: 'Good match - confirm this mapping before autofill',
        priority: 'low'
      };
    }

    // Low confidence - verify carefully
    return {
      action: 'verify',
      message: 'Weak match - please verify this mapping carefully',
      priority: 'medium'
    };
  }

  /**
   * Categorize fields by confidence level
   */
  categorizeByConfidence(matchDetails) {
    return {
      highConfidence: matchDetails.filter(d => d.confidence >= this.CONFIDENCE_THRESHOLDS.HIGH),
      mediumConfidence: matchDetails.filter(d => 
        d.confidence >= this.CONFIDENCE_THRESHOLDS.MEDIUM && 
        d.confidence < this.CONFIDENCE_THRESHOLDS.HIGH
      ),
      lowConfidence: matchDetails.filter(d => 
        d.confidence > 0 && 
        d.confidence < this.CONFIDENCE_THRESHOLDS.MEDIUM
      ),
      noMatch: matchDetails.filter(d => d.confidence === 0)
    };
  }

  /**
   * Analyze form and match with user data (Enhanced with confidence and explanations)
   */
  analyzeForm(formFields, userData) {
    const userDataMap = this.getUserDataMap(userData);
    const matchedFields = [];
    const missingFields = [];
    const matchDetails = [];

    formFields.forEach(field => {
      const normalizedField = this.normalizeFieldName(field);
      const matchResult = this.findFieldMatch(normalizedField, userDataMap);

      const detail = {
        fieldName: field,
        normalizedName: normalizedField,
        status: matchResult.matched ? 'matched' : 'missing',
        mappedTo: matchResult.mappedTo,
        value: matchResult.value,
        confidence: matchResult.confidence,
        reason: matchResult.reason,
        canAutofill: matchResult.confidence >= this.CONFIDENCE_THRESHOLDS.AUTOFILL_MIN,
        suggestion: this.generateSuggestion(field, matchResult)
      };

      matchDetails.push(detail);

      if (matchResult.matched) {
        matchedFields.push(field);
      } else {
        missingFields.push(field);
      }
    });

    // Calculate weighted match percentage (considering confidence)
    const totalConfidence = matchDetails.reduce((sum, d) => sum + d.confidence, 0);
    const matchPercentage = formFields.length > 0
      ? Math.round((totalConfidence / formFields.length) * 100)
      : 0;

    // Categorize by confidence
    const confidenceCategories = this.categorizeByConfidence(matchDetails);

    // Generate actionable insights
    const insights = this.generateInsights(matchDetails, confidenceCategories);

    // Prepare autofill data
    const autofillData = this.prepareAutofillData(matchDetails);

    return {
      totalFields: formFields.length,
      matchedFields,
      missingFields,
      matchPercentage,
      matchDetails,
      confidenceBreakdown: {
        high: confidenceCategories.highConfidence.length,
        medium: confidenceCategories.mediumConfidence.length,
        low: confidenceCategories.lowConfidence.length,
        none: confidenceCategories.noMatch.length
      },
      analysis: {
        readyToAutofill: matchDetails.filter(d => d.canAutofill).length,
        needsInput: missingFields.length,
        needsVerification: confidenceCategories.mediumConfidence.length + confidenceCategories.lowConfidence.length,
        completionStatus: matchPercentage >= 80 ? 'excellent' : 
                         matchPercentage >= 50 ? 'good' : 'incomplete',
        averageConfidence: formFields.length > 0 ? 
          (totalConfidence / formFields.length).toFixed(2) : 0
      },
      insights,
      autofillData
    };
  }

  /**
   * Generate actionable insights
   */
  generateInsights(matchDetails, confidenceCategories) {
    const insights = [];

    // High confidence fields
    if (confidenceCategories.highConfidence.length > 0) {
      insights.push({
        type: 'success',
        icon: '✅',
        title: 'Ready for Autofill',
        message: `${confidenceCategories.highConfidence.length} field(s) can be auto-filled with high confidence`,
        fields: confidenceCategories.highConfidence.map(d => d.fieldName)
      });
    }

    // Medium confidence fields
    if (confidenceCategories.mediumConfidence.length > 0) {
      insights.push({
        type: 'warning',
        icon: '⚠️',
        title: 'Needs Verification',
        message: `${confidenceCategories.mediumConfidence.length} field(s) have medium confidence - please verify`,
        fields: confidenceCategories.mediumConfidence.map(d => d.fieldName)
      });
    }

    // Low confidence fields
    if (confidenceCategories.lowConfidence.length > 0) {
      insights.push({
        type: 'caution',
        icon: '⚡',
        title: 'Low Confidence Matches',
        message: `${confidenceCategories.lowConfidence.length} field(s) have weak matches - manual review recommended`,
        fields: confidenceCategories.lowConfidence.map(d => d.fieldName)
      });
    }

    // Missing fields
    if (confidenceCategories.noMatch.length > 0) {
      insights.push({
        type: 'error',
        icon: '❌',
        title: 'Missing Data',
        message: `${confidenceCategories.noMatch.length} field(s) require data - upload documents or enter manually`,
        fields: confidenceCategories.noMatch.map(d => d.fieldName),
        action: {
          label: 'Upload Documents',
          route: '/dashboard/documents'
        }
      });
    }

    return insights;
  }

  /**
   * Prepare data for autofill system
   */
  prepareAutofillData(matchDetails) {
    const autofillable = matchDetails.filter(d => d.canAutofill);
    
    return {
      canAutofill: autofillable.length > 0,
      fieldCount: autofillable.length,
      fields: autofillable.map(d => ({
        fieldName: d.fieldName,
        normalizedName: d.normalizedName,
        value: d.value,
        confidence: d.confidence,
        mappedFrom: d.mappedTo
      }))
    };
  }

  /**
   * Generate AI context for RAG integration
   */
  generateAIContext(analysisResult) {
    const { matchDetails, analysis, insights } = analysisResult;
    
    const context = {
      summary: `Form analysis complete: ${analysis.readyToAutofill} fields ready, ${analysis.needsInput} missing, ${analysis.needsVerification} need verification.`,
      completionRate: `${analysisResult.matchPercentage}% complete with ${analysis.averageConfidence} average confidence.`,
      missingFields: analysisResult.missingFields,
      lowConfidenceFields: matchDetails
        .filter(d => d.confidence > 0 && d.confidence < 0.8)
        .map(d => ({ field: d.fieldName, confidence: d.confidence })),
      recommendations: insights.map(i => i.message),
      nextSteps: this.generateNextSteps(analysisResult)
    };

    return context;
  }

  /**
   * Generate next steps recommendations
   */
  generateNextSteps(analysisResult) {
    const steps = [];
    const { analysis, missingFields, matchDetails } = analysisResult;

    if (analysis.readyToAutofill > 0) {
      steps.push({
        priority: 1,
        action: 'Use autofill for high-confidence fields',
        description: `${analysis.readyToAutofill} fields are ready to be auto-filled`
      });
    }

    if (analysis.needsVerification > 0) {
      steps.push({
        priority: 2,
        action: 'Verify medium-confidence matches',
        description: 'Review and confirm field mappings before autofill'
      });
    }

    if (missingFields.length > 0) {
      const missingFieldsList = missingFields.slice(0, 3).join(', ');
      steps.push({
        priority: 3,
        action: 'Upload documents or enter data manually',
        description: `Missing: ${missingFieldsList}${missingFields.length > 3 ? '...' : ''}`
      });
    }

    return steps;
  }

  /**
   * Process uploaded form file
   */
  async analyzeUploadedForm(filePath, userData) {
    try {
      console.log('Analyzing uploaded form:', filePath);
      
      // Extract text from form
      const extractedText = await ocrService.extractText(filePath);
      console.log('OCR extraction complete. Text length:', extractedText?.length || 0);
      
      if (!extractedText || extractedText.trim().length === 0) {
        console.warn('No text extracted from form');
        return {
          success: false,
          error: 'No text could be extracted from the form. The file may be empty, corrupted, or contain only images without text.',
          totalFields: 0,
          matchedFields: [],
          missingFields: [],
          matchPercentage: 0,
          matchDetails: [],
          confidenceBreakdown: { high: 0, medium: 0, low: 0, none: 0 },
          analysis: {
            readyToAutofill: 0,
            needsInput: 0,
            needsVerification: 0,
            completionStatus: 'incomplete',
            averageConfidence: '0'
          },
          insights: [{
            type: 'error',
            icon: '❌',
            title: 'No Text Extracted',
            message: 'Could not extract text from the uploaded form. Try a different file or use the "Simulate Fields" mode.',
            fields: []
          }],
          autofillData: { canAutofill: false, fieldCount: 0, fields: [] }
        };
      }
      
      // Extract form fields
      const formFields = this.extractFormFields(extractedText);
      console.log('Form fields extracted:', formFields);
      
      if (formFields.length === 0) {
        console.warn('No form fields detected in extracted text');
        return {
          success: false,
          error: 'No form fields detected. The document may not contain recognizable form fields.',
          extractedText: extractedText.substring(0, 500),
          totalFields: 0,
          matchedFields: [],
          missingFields: [],
          matchPercentage: 0,
          matchDetails: [],
          confidenceBreakdown: { high: 0, medium: 0, low: 0, none: 0 },
          analysis: {
            readyToAutofill: 0,
            needsInput: 0,
            needsVerification: 0,
            completionStatus: 'incomplete',
            averageConfidence: '0'
          },
          insights: [{
            type: 'warning',
            icon: '⚠️',
            title: 'No Form Fields Detected',
            message: 'The document was read but no form fields were detected. Try using "Simulate Fields" mode to manually enter field names.',
            fields: []
          }],
          autofillData: { canAutofill: false, fieldCount: 0, fields: [] }
        };
      }
      
      // Analyze against user data
      const analysis = this.analyzeForm(formFields, userData);
      
      return {
        success: true,
        extractedText: extractedText.substring(0, 500), // Preview only
        ...analysis
      };
    } catch (error) {
      console.error('Form analysis error:', error);
      throw new Error(`Failed to analyze form: ${error.message}`);
    }
  }

  /**
   * Analyze mock/simulated form fields
   */
  analyzeMockForm(mockFields, userData) {
    return {
      success: true,
      ...this.analyzeForm(mockFields, userData)
    };
  }
}

module.exports = new FormAnalyzerService();
