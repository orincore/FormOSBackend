/**
 * FormOS Security V2 Feature Flags Configuration
 * All V2 features default to disabled (false).
 * They can be enabled by setting the corresponding environment variables to 'true'.
 */

const getFlag = (envVar) => {
  return process.env[envVar] === 'true';
};

const getFlags = () => ({
  SECURITY_V2_ENABLED: getFlag('SECURITY_V2_ENABLED'),
  CLIENT_SIDE_ENCRYPTION_ENABLED: getFlag('CLIENT_SIDE_ENCRYPTION_ENABLED'),
  SECURE_DOCUMENT_UPLOAD_ENABLED: getFlag('SECURE_DOCUMENT_UPLOAD_ENABLED'),
  GRIDFS_ENABLED: getFlag('GRIDFS_ENABLED'),
  SECURE_AI_MODE_ENABLED: getFlag('SECURE_AI_MODE_ENABLED'),
  MIGRATION_ENABLED: getFlag('MIGRATION_ENABLED'),
});

module.exports = {
  getFlags,
  // Static access to loaded configurations
  flags: getFlags(),
};
