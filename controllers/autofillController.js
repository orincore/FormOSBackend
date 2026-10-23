const User = require('../models/User');
const Document = require('../models/Document');
const { HIDDEN_KEYS, labelOf, isSensitive } = require('../services/documentFields');

exports.getAutofillData = async (req, res) => {
  try {
    const user = await User.findById(req.userId);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    const includeSensitive = String(req.query.includeSensitive || '').toLowerCase() === 'true';

    if (includeSensitive && !req.stepUpVerified) {
      return res.status(403).json({
        success: false,
        code: 'STEP_UP_REQUIRED',
        message: 'Recent re-authentication is required before sensitive autofill.',
      });
    }

    // Query all documents associated with user to aggregate extracted information
    // Newest first, so when two documents disagree the more recent one wins.
    const docs = await Document.find({ userId: req.userId }).sort({ createdAt: -1 });

    const aggregated = {};
    for (const doc of docs) {
      const s = doc.structuredData || {};
      for (const [k, v] of Object.entries(s)) {
        if (v && !aggregated[k]) {
          aggregated[k] = v;
        }
      }
      if (!aggregated.gender && doc.extractedText) {
        if (/महिला|\bFEMALE\b|\bFemale\b/i.test(doc.extractedText)) {
          aggregated.gender = 'Female';
        } else if (/पुरुष|\bMALE\b|\bMale\b/i.test(doc.extractedText)) {
          aggregated.gender = 'Male';
        }
      }
      if (!aggregated.voterId && doc.extractedText) {
        const vm = doc.extractedText.match(/\b([A-Z]{3}\d{7})\b/i);
        if (vm) {
          aggregated.voterId = vm[1].toUpperCase();
        }
      }
    }

    // Determine clean name components
    const fullName = user.name || user.extractedData?.fullName || aggregated.fullName || '';
    const nameParts = fullName.trim().split(/\s+/);
    const firstName = aggregated.firstName || user.extractedData?.firstName || nameParts[0] || '';
    const lastName = aggregated.lastName || user.extractedData?.lastName || (nameParts.length > 1 ? nameParts[nameParts.length - 1] : '');
    const middleName = aggregated.middleName || user.extractedData?.middleName || (nameParts.length > 2 ? nameParts.slice(1, -1).join(' ') :'');

    const primaryPhone = user.phone || user.extractedData?.phone || aggregated.phone || '';
    const docPhone = aggregated.phone || '';
    const alternatePhone = (docPhone && docPhone !== primaryPhone) ? docPhone : (user.extractedData?.alternatePhone || primaryPhone || '');

    const dateOfBirth = aggregated.dateOfBirth || aggregated.dob || user.extractedData?.dateOfBirth || '';
    const aadhaar = aggregated.aadhaarNumber || aggregated.aadhaar || user.extractedData?.aadhaarNumber || '';
    const pan = aggregated.panNumber || aggregated.pan || user.extractedData?.panNumber || '';
    const address = aggregated.address || user.extractedData?.address || '';
    const addressLine1 = aggregated.addressLine1 || aggregated.street || user.extractedData?.addressLine1 || '';
    const addressLine2 = aggregated.addressLine2 || user.extractedData?.addressLine2 || '';
    const city = aggregated.city || user.extractedData?.city || '';
    const district = aggregated.district || aggregated.city || user.extractedData?.district || '';
    const state = aggregated.state || user.extractedData?.state || '';
    const zipCode = aggregated.zipCode || aggregated.pincode || aggregated.zip || aggregated.postalCode || user.extractedData?.zipCode || '';
    const gender = aggregated.gender || user.extractedData?.gender || '';
    const nationality = aggregated.nationality || user.extractedData?.nationality || 'Indian';

    // Synchronize extractedData onto user in MongoDB if missing
    if (!user.extractedData?.aadhaarNumber && aadhaar) {
      await User.findByIdAndUpdate(user._id, {
        $set: {
          'extractedData.fullName': fullName,
          'extractedData.dateOfBirth': dateOfBirth,
          'extractedData.aadhaarNumber': aadhaar,
          'extractedData.panNumber': pan,
          'extractedData.address': address,
          'extractedData.phone': primaryPhone,
          'extractedData.email': user.email,
          'extractedData.gender': gender,
        }
      }).catch(err => console.error('Failed to sync user.extractedData:', err.message));
    }

    // Generic address sub-component extraction if address exists but sub-fields are empty
    let finalAddressLine1 = addressLine1;
    let finalCity = city;
    let finalState = state;
    let finalZipCode = zipCode;

    if (address && (!finalAddressLine1 || !finalCity || !finalState || !finalZipCode)) {
      const parts = address.split(/[,\n]+/).map(s => s.trim()).filter(Boolean);
      for (const p of parts) {
        const pinMatch = p.match(/\b(\d{6})\b/);
        if (pinMatch && !finalZipCode) finalZipCode = pinMatch[1];
      }
      if (!finalAddressLine1 && parts.length > 0) finalAddressLine1 = parts[0];
      if (!finalCity && parts.length > 2) finalCity = parts[parts.length - 2];
      if (!finalState && parts.length > 1) {
        const sMatch = parts[parts.length - 1].replace(/\d{6}/, '').replace(/[-–]/, '').trim();
        if (sMatch) finalState = sMatch;
      }
    }

    // Build comprehensive autofill payload
    const fullAutofillData = {
      name: fullName,
      fullName,
      firstName,
      middleName,
      lastName,
      email: user.email || '',
      phone: primaryPhone,
      alternatePhone,
      dateOfBirth,
      gender,
      nationality,
      address,
      addressLine1: finalAddressLine1,
      addressLine2,
      city: finalCity,
      district: district || finalCity,
      state: finalState,
      zipCode: finalZipCode,
      fatherName: aggregated.fatherName || user.extractedData?.fatherName || '',
      country: 'India',
      aadhaar,
      pan,
      voterId: aggregated.voterId || user.extractedData?.voterId || '',
      passportNumber: aggregated.passportNumber || user.extractedData?.passportNumber || '',
      drivingLicence: aggregated.drivingLicenseNumber || aggregated.drivingLicence || aggregated.license || user.extractedData?.drivingLicence || '',
    };

    // Every other labelled field read from the member's documents (roll number, seat number, class of vehicle ...),
    // so the extension can match a form's own labels instead of only the fixed set above.
    const fields = [];
    const seenKeys = new Set();
    for (const [key, value] of Object.entries(aggregated)) {
      if (HIDDEN_KEYS.has(key) || seenKeys.has(key)) continue;
      const text = typeof value === 'string' ? value.trim() : typeof value === 'number' ? String(value) : '';
      if (!text) continue;
      const label = labelOf(key);
      const sensitive = isSensitive(key, label, text);
      if (sensitive && !includeSensitive) continue;
      seenKeys.add(key);
      fields.push({ key, label, value: text });
    }

    let payload;
    if (!includeSensitive) {
      payload = {
        data: {
          name: fullAutofillData.name,
          fullName: fullAutofillData.fullName,
          firstName: fullAutofillData.firstName,
          middleName: fullAutofillData.middleName,
          lastName: fullAutofillData.lastName,
          gender: fullAutofillData.gender,
          nationality: fullAutofillData.nationality,
          address: fullAutofillData.address,
          addressLine1: fullAutofillData.addressLine1,
          addressLine2: fullAutofillData.addressLine2,
          city: fullAutofillData.city,
          district: fullAutofillData.district,
          state: fullAutofillData.state,
          zipCode: fullAutofillData.zipCode,
          country: fullAutofillData.country,
        },
        fields,
        requiresStepUp: true,
        protectedFields: ['email', 'phone', 'dateOfBirth', 'aadhaar', 'pan'],
      };
    } else {
      payload = {
        data: fullAutofillData,
        fields,
        requiresStepUp: false,
        protectedFields: [],
      };
    }

    return res.json({
      success: true,
      ...payload,
      stepUpExpiresAt: req.authSession?.stepUpExpiresAt || null,
    });
  } catch (error) {
    console.error('Autofill error:', error);
    return res.status(500).json({
      success: false,
      message: 'Error fetching autofill data',
    });
  }
};
