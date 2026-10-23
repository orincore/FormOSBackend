// The details FormOS keeps for a member, the rules each must follow, and which of them are ID numbers. One place, used by the
// WhatsApp assistant, the "My data" page and the API, so a value is valid (or not) the same way everywhere.
const ocrService = require('./ocrService');
const docFields = require('./documentFields');

const FIELD_LABEL = {
  fullName: 'Name', fatherName: "Father's name", dateOfBirth: 'Date of birth', gender: 'Gender',
  aadhaarNumber: 'Aadhaar', panNumber: 'PAN', passportNumber: 'Passport', drivingLicenseNumber: 'Licence',
  address: 'Address', pincode: 'PIN code', state: 'State', phone: 'Phone', email: 'Email',
};
const SENSITIVE = new Set(['aadhaarNumber', 'panNumber', 'passportNumber', 'drivingLicenseNumber']);

// ---- validation for data saved from the chat ---------------------------------------------------------------
const STATES = /^[A-Za-z .&-]{2,40}$/;
function cleanField(key, raw) {
  const v = String(raw ?? '').trim();
  if (!v) return { error: 'it was empty' };
  switch (key) {
    case 'fullName': case 'fatherName':
      return /^[A-Za-z][A-Za-z .'-]{1,79}$/.test(v) ? { value: v.replace(/\s+/g, ' ') } : { error: 'a name should be letters only' };
    case 'dateOfBirth': {
      const iso = v.match(/^(\d{4})-(\d{2})-(\d{2})$/);
      const dmy = v.match(/^(\d{1,2})[\/.-](\d{1,2})[\/.-](\d{4})$/);
      const [d, m, y] = iso ? [iso[3], iso[2], iso[1]] : dmy ? [dmy[1], dmy[2], dmy[3]] : [];
      if (!y || Number(m) < 1 || Number(m) > 12 || Number(d) < 1 || Number(d) > 31 || Number(y) < 1900 || Number(y) > new Date().getFullYear()) return { error: 'use a date like 14/03/1996' };
      return { value: `${String(d).padStart(2, '0')}/${String(m).padStart(2, '0')}/${y}` };
    }
    case 'gender': {
      const g = v.toLowerCase();
      if (/^(m|male|man)$/.test(g)) return { value: 'Male' };
      if (/^(f|female|woman)$/.test(g)) return { value: 'Female' };
      if (/^(other|transgender|non.?binary)$/.test(g)) return { value: 'Other' };
      return { error: 'use Male, Female or Other' };
    }
    case 'aadhaarNumber': {
      const d = v.replace(/\D/g, '');
      return ocrService.isValidAadhaar(d) ? { value: d } : { error: 'that is not a valid Aadhaar number' };
    }
    case 'panNumber': {
      const p = v.toUpperCase().replace(/\s/g, '');
      return /^[A-Z]{5}\d{4}[A-Z]$/.test(p) ? { value: p } : { error: 'a PAN looks like ABCDE1234F' };
    }
    case 'passportNumber': {
      const p = v.toUpperCase().replace(/\s/g, '');
      return /^[A-Z]\d{7}$/.test(p) ? { value: p } : { error: 'a passport number looks like K1234567' };
    }
    case 'drivingLicenseNumber': {
      // The same rule the document reader applies, so a number the system saved can always be corrected to another of the same shape.
      const p = v.toUpperCase().replace(/\s+/g, ' ').trim();
      return docFields.valueFitsKey('drivingLicenseNumber', p) ? { value: p } : { error: 'a licence number has letters and digits, for example MH05 20220000041' };
    }
    case 'address': return v.length >= 6 && v.length <= 300 ? { value: v.replace(/\s+/g, ' ') } : { error: 'the address should be 6 to 300 characters' };
    case 'pincode': return /^[1-9]\d{5}$/.test(v) ? { value: v } : { error: 'a PIN code has 6 digits' };
    case 'state': return STATES.test(v) ? { value: v } : { error: 'that does not look like a state' };
    case 'phone': {
      const d = v.replace(/\D/g, '').replace(/^(91|0)(?=\d{10}$)/, '');
      return /^[6-9]\d{9}$/.test(d) ? { value: d } : { error: 'a mobile number has 10 digits' };
    }
    case 'email': return /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(v) && v.length <= 120 ? { value: v.toLowerCase() } : { error: 'that is not a valid email' };
    default: return { error: 'I do not save that field' };
  }
}

function cleanFields(fields = {}, custom = {}) {
  const ok = {}; const bad = [];
  for (const [key, raw] of Object.entries(fields || {})) {
    if (!FIELD_LABEL[key]) { bad.push(`${key}: I do not save that field`); continue; }
    const r = cleanField(key, raw);
    if (r.error) bad.push(`${FIELD_LABEL[key]}: ${r.error}`); else ok[key] = r.value;
  }
  const extra = {};
  for (const [label, raw] of Object.entries(custom || {}).slice(0, 10)) {
    const k = String(label).trim().replace(/[^A-Za-z0-9 _-]/g, '').slice(0, 40);
    const v = String(raw ?? '').trim().slice(0, 200);
    if (k && v) extra[k] = v; else bad.push(`${label || 'note'}: it was empty`);
  }
  return { ok, extra, bad };
}


module.exports = { FIELD_LABEL, SENSITIVE, cleanField, cleanFields };
