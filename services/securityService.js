const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const DEFAULT_STEP_UP_MINUTES = parseInt(process.env.STEP_UP_TTL_MINUTES || '10', 10);
const DEFAULT_TRUSTED_DEVICE_DAYS = parseInt(process.env.TRUSTED_DEVICE_DAYS || '30', 10);

const SENSITIVE_FIELDS = new Set([
  'aadhaarNumber',
  'panNumber',
  'dateOfBirth',
  'phone',
  'email',
  'address',
]);

const HIGH_RISK_AUTOFILL_FIELDS = new Set(['aadhaar', 'pan', 'dateOfBirth', 'phone', 'email']);

const getEncryptionKey = () => {
  const source = process.env.MFA_ENCRYPTION_KEY || process.env.JWT_SECRET || 'formos-dev-fallback';
  return crypto.createHash('sha256').update(source).digest();
};

const encryptText = (plainText) => {
  if (!plainText) {
    return { encrypted: null, iv: null, authTag: null };
  }

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getEncryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    encrypted: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
  };
};

const decryptText = ({ encrypted, iv, authTag }) => {
  if (!encrypted || !iv || !authTag) {
    return null;
  }

  try {
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      getEncryptionKey(),
      Buffer.from(iv, 'base64')
    );
    decipher.setAuthTag(Buffer.from(authTag, 'base64'));

    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encrypted, 'base64')),
      decipher.final(),
    ]);

    return decrypted.toString('utf8');
  } catch (error) {
    const decryptionError = new Error('Stored MFA secret could not be decrypted');
    decryptionError.code = 'MFA_SECRET_DECRYPT_FAILED';
    decryptionError.status = 500;
    throw decryptionError;
  }
};

const generateMfaSecret = (email) => {
  return speakeasy.generateSecret({
    name: `FormOS (${email})`,
    issuer: 'FormOS',
    length: 32,
  });
};

const buildQrCodeDataUrl = async (otpauthUrl) => {
  return QRCode.toDataURL(otpauthUrl, { margin: 1, width: 220 });
};

const normalizeCode = (code = '') => code.replace(/\s+/g, '').trim();

const generateNumericOtp = (length = 6) => {
  const max = 10 ** length;
  return crypto.randomInt(0, max).toString().padStart(length, '0');
};

const hashValue = async (value) => bcrypt.hash(value, 10);

const compareHashedValue = async (value, hashedValue) => {
  if (!value || !hashedValue) {
    return false;
  }

  return bcrypt.compare(value, hashedValue);
};

const verifyTotpCode = (secret, token) => {
  return speakeasy.totp.verify({
    secret,
    encoding: 'base32',
    token: normalizeCode(token),
    window: 1,
  });
};

const createRecoveryCodes = async (count = 8) => {
  const plainCodes = Array.from({ length: count }, () =>
    crypto.randomBytes(4).toString('hex').toUpperCase()
  );
  const hashedCodes = await Promise.all(plainCodes.map((code) => bcrypt.hash(code, 10)));
  return { plainCodes, hashedCodes };
};

const consumeRecoveryCode = async (submittedCode, hashedCodes = []) => {
  const normalized = normalizeCode(submittedCode).toUpperCase();

  for (let index = 0; index < hashedCodes.length; index += 1) {
    const hash = hashedCodes[index];
    if (await bcrypt.compare(normalized, hash)) {
      const remainingHashes = hashedCodes.filter((_, codeIndex) => codeIndex !== index);
      return { matched: true, remainingHashes };
    }
  }

  return { matched: false, remainingHashes: hashedCodes };
};

const hashIpAddress = (ipAddress = '') => {
  return crypto.createHash('sha256').update(ipAddress).digest('hex');
};

const getClientIp = (req) => {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length > 0) {
    return forwarded.split(',')[0].trim();
  }
  return req.ip || req.connection?.remoteAddress || '';
};

const getDeviceContext = (req) => {
  const deviceIdHeader = req.headers['x-device-id'];
  const deviceNameHeader = req.headers['x-device-name'];
  const clientTypeHeader = req.headers['x-client-type'];

  return {
    deviceId: typeof deviceIdHeader === 'string' && deviceIdHeader.trim()
      ? deviceIdHeader.trim()
      : `ephemeral-${hashIpAddress(`${req.headers['user-agent'] || ''}:${getClientIp(req)}`).slice(0, 16)}`,
    deviceName: typeof deviceNameHeader === 'string' && deviceNameHeader.trim()
      ? deviceNameHeader.trim().slice(0, 120)
      : 'Unknown device',
    clientType: typeof clientTypeHeader === 'string' && clientTypeHeader.trim()
      ? clientTypeHeader.trim()
      : 'web',
    userAgent: req.headers['user-agent'] || '',
    ipHash: hashIpAddress(getClientIp(req)),
  };
};

const maskString = (value) => {
  if (!value) return '';
  if (value.length <= 4) return '*'.repeat(value.length);
  return `${'*'.repeat(Math.max(4, value.length - 4))}${value.slice(-4)}`;
};

const maskEmail = (value) => {
  if (!value || !value.includes('@')) return maskString(value);
  const [localPart, domain] = value.split('@');
  if (localPart.length <= 2) return `${localPart[0] || '*'}***@${domain}`;
  return `${localPart[0]}***${localPart.slice(-1)}@${domain}`;
};

const maskPhone = (value) => {
  if (!value) return '';
  const digits = value.replace(/\D/g, '');
  if (digits.length <= 4) return '*'.repeat(digits.length);
  return `${'*'.repeat(Math.max(4, digits.length - 4))}${digits.slice(-4)}`;
};

const maskValueByField = (field, value) => {
  if (!value) return value;

  if (field === 'email') return maskEmail(String(value));
  if (field === 'phone') return maskPhone(String(value));

  if (field === 'dateOfBirth') {
    const stringValue = String(value);
    if (stringValue.length < 4) return '****';
    return `**/**/${stringValue.slice(-4)}`;
  }

  if (field === 'address') {
    const stringValue = String(value);
    return stringValue.length > 12 ? `${stringValue.slice(0, 8)}...` : '********';
  }

  return maskString(String(value));
};

const maskStructuredData = (data = {}) => {
  const masked = { ...data };

  Object.keys(masked).forEach((field) => {
    if (SENSITIVE_FIELDS.has(field)) {
      masked[field] = maskValueByField(field, masked[field]);
    }
  });

  return masked;
};

const maskSensitiveText = (text = '') => {
  return text
    .replace(/\b\d{4}\s?\d{4}\s?\d{4}\b/g, (match) => `********${match.replace(/\s/g, '').slice(-4)}`)
    .replace(/\b[A-Z]{5}\d{4}[A-Z]\b/g, (match) => `****${match.slice(-4)}`)
    .replace(/\b\d{10}\b/g, (match) => `${'*'.repeat(6)}${match.slice(-4)}`)
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, (match) => maskEmail(match));
};

const splitAutofillPayload = (data = {}, includeSensitive = false) => {
  const safePayload = {
    name: data.name || '',
    firstName: data.firstName || '',
    lastName: data.lastName || '',
    address: data.address || '',
    dateOfBirth: data.dateOfBirth || '',
  };

  if (!includeSensitive) {
    return {
      data: safePayload,
      requiresStepUp: true,
      protectedFields: Array.from(HIGH_RISK_AUTOFILL_FIELDS),
    };
  }

  return {
    data: {
      ...safePayload,
      email: data.email || '',
      phone: data.phone || '',
      aadhaar: data.aadhaar || '',
      pan: data.pan || '',
    },
    requiresStepUp: false,
    protectedFields: [],
  };
};

const buildStepUpExpiry = () => {
  return new Date(Date.now() + DEFAULT_STEP_UP_MINUTES * 60 * 1000);
};

const buildTrustedUntil = (days = DEFAULT_TRUSTED_DEVICE_DAYS) => {
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000);
};

module.exports = {
  DEFAULT_STEP_UP_MINUTES,
  DEFAULT_TRUSTED_DEVICE_DAYS,
  SENSITIVE_FIELDS,
  HIGH_RISK_AUTOFILL_FIELDS,
  buildQrCodeDataUrl,
  buildStepUpExpiry,
  buildTrustedUntil,
  compareHashedValue,
  consumeRecoveryCode,
  createRecoveryCodes,
  decryptText,
  encryptText,
  generateNumericOtp,
  generateMfaSecret,
  getClientIp,
  getDeviceContext,
  hashValue,
  hashIpAddress,
  maskSensitiveText,
  maskStructuredData,
  maskValueByField,
  normalizeCode,
  splitAutofillPayload,
  verifyTotpCode,
};
