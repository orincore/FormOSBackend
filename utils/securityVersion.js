/**
 * Resolves the security version for a given entity (User, Document, etc.).
 * Guarantees that if securityVersion is missing, invalid, or 1, it defaults to V1 (1).
 * Security V2 is only resolved if the entity's version is explicitly set to 2.
 * 
 * @param {Object} entity - The Mongoose document or raw object to evaluate.
 * @returns {Number} Resolves to 1 (V1) or 2 (V2).
 */
const getSecurityVersion = (entity) => {
  if (entity && entity.securityVersion === 2) {
    return 2;
  }
  return 1;
};

module.exports = {
  getSecurityVersion,
};
