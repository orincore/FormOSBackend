/**
 * FormOS Security V2 Foundation Verification Script
 * Validates feature flags, centralized version resolving, Mongoose schema constraints,
 * and V1/V2 coexistence logic.
 * 
 * Usage: node test-security-v2-foundation.js
 */

require('dotenv').config({ path: __dirname + '/.env' });
const assert = require('assert');
const mongoose = require('mongoose');
const User = require('./models/User');
const Document = require('./models/Document');
const PendingRegistration = require('./models/PendingRegistration');
const { flags } = require('./config/featureFlags');
const { getSecurityVersion } = require('./utils/securityVersion');

async function runTests() {
  console.log('🧪 Starting Security V2 Foundation Tests...\n');

  // Test Case 1: Validate default disabled state of feature flags
  console.log('🔍 Test Case 1: Checking default state of V2 feature flags...');
  try {
    assert.strictEqual(flags.SECURITY_V2_ENABLED, false, 'SECURITY_V2_ENABLED must default to false');
    assert.strictEqual(flags.CLIENT_SIDE_ENCRYPTION_ENABLED, false, 'CLIENT_SIDE_ENCRYPTION_ENABLED must default to false');
    assert.strictEqual(flags.SECURE_DOCUMENT_UPLOAD_ENABLED, false, 'SECURE_DOCUMENT_UPLOAD_ENABLED must default to false');
    assert.strictEqual(flags.GRIDFS_ENABLED, false, 'GRIDFS_ENABLED must default to false');
    assert.strictEqual(flags.SECURE_AI_MODE_ENABLED, false, 'SECURE_AI_MODE_ENABLED must default to false');
    assert.strictEqual(flags.MIGRATION_ENABLED, false, 'MIGRATION_ENABLED must default to false');
    console.log('✅ All V2 feature flags successfully defaulted to disabled.\n');
  } catch (error) {
    console.error('❌ Test Case 1 Failed:', error.message);
    throw error;
  }

  // Test Case 2: Centralized version resolving helper
  console.log('🔍 Test Case 2: Testing getSecurityVersion(entity) helper...');
  try {
    assert.strictEqual(getSecurityVersion(null), 1, 'Null entity must resolve to V1');
    assert.strictEqual(getSecurityVersion(undefined), 1, 'Undefined entity must resolve to V1');
    assert.strictEqual(getSecurityVersion({}), 1, 'Empty object must resolve to V1');
    assert.strictEqual(getSecurityVersion({ securityVersion: 1 }), 1, 'securityVersion = 1 must resolve to V1');
    assert.strictEqual(getSecurityVersion({ securityVersion: 2 }), 2, 'securityVersion = 2 must resolve to V2');
    assert.strictEqual(getSecurityVersion({ securityVersion: 3 }), 1, 'Unknown legacy value must safely fall back to V1');
    assert.strictEqual(getSecurityVersion({ name: 'John Doe' }), 1, 'Entity missing version field must resolve to V1');
    console.log('✅ Centralized getSecurityVersion helper validated successfully.\n');
  } catch (error) {
    console.error('❌ Test Case 2 Failed:', error.message);
    throw error;
  }

  // Database Connection
  console.log('🔌 Connecting to MongoDB for Schema verification...');
  if (!process.env.MONGODB_URI) {
    console.error('❌ MONGODB_URI not found in .env file');
    process.exit(1);
  }
  await mongoose.connect(process.env.MONGODB_URI);
  console.log('✅ Connected to database.\n');

  // Clean up any stray test accounts
  const testEmail = 'v2-test-temp@formos.online';
  await User.deleteMany({ email: testEmail });
  await PendingRegistration.deleteMany({ email: testEmail });

  // Test Case 3: Database validation and co-existence tests
  console.log('🔍 Test Case 3: Verifying Mongoose Model schemas & validation...');
  try {
    // 3.1: Verify default schema values (V1 fallback)
    console.log('   - Testing User V1 defaults...');
    const userV1 = await User.create({
      email: testEmail,
      name: 'V1 Test User',
      pin: '123456'
    });
    assert.strictEqual(userV1.securityVersion, 1, 'Newly created user should default to version 1');
    assert.strictEqual(userV1.migrationStatus, 'pending', 'Newly created user migrationStatus should default to pending');
    assert.strictEqual(getSecurityVersion(userV1), 1, 'getSecurityVersion helper should resolve user as V1');

    // 3.2: Verify explicit version 2 representation
    console.log('   - Testing User V2 representation...');
    const userV2 = await User.create({
      email: 'v2-test-temp-2@formos.online',
      name: 'V2 Test User',
      pin: '123456',
      securityVersion: 2
    });
    assert.strictEqual(userV2.securityVersion, 2, 'V2 user must store securityVersion = 2');
    assert.strictEqual(getSecurityVersion(userV2), 2, 'getSecurityVersion helper should resolve user as V2');

    // 3.3: Verify validation constraints (Invalid security version)
    console.log('   - Testing User invalid version constraint...');
    try {
      await User.create({
        email: 'v2-test-temp-3@formos.online',
        name: 'Invalid User',
        pin: '123456',
        securityVersion: 3
      });
      assert.fail('User should have failed schema validation with invalid securityVersion (3)');
    } catch (validationErr) {
      assert.ok(validationErr.errors.securityVersion, 'Validation error must target the securityVersion field');
      console.log('     ✓ Invalid security version failed validation successfully.');
    }

    // 3.4: Verify document model default storage and version constraints
    console.log('   - Testing Document V1 and V2 models...');
    const docV1 = new Document({
      userId: userV1._id,
      filename: 'test.pdf',
      originalName: 'test.pdf',
      filePath: '/uploads/test.pdf',
      fileSize: 1024,
      mimeType: 'application/pdf',
      storageType: 'local'
    });
    await docV1.save();
    assert.strictEqual(docV1.securityVersion, 1, 'Document should default to version 1');
    assert.strictEqual(docV1.storageType, 'local', 'Document storageType should default to local');

    // V2 Document with gridfs enum value
    const docV2 = new Document({
      userId: userV1._id,
      filename: 'test-v2.pdf',
      originalName: 'test-v2.pdf',
      filePath: 'gridfs-key',
      fileSize: 2048,
      mimeType: 'application/pdf',
      storageType: 'gridfs',
      securityVersion: 2
    });
    await docV2.save();
    assert.strictEqual(docV2.securityVersion, 2, 'V2 document must store securityVersion = 2');
    assert.strictEqual(docV2.storageType, 'gridfs', 'V2 document must support gridfs storageType');

    // Clean up database modifications
    console.log('🧹 Cleaning up database test records...');
    await User.deleteMany({ email: { $in: [testEmail, 'v2-test-temp-2@formos.online'] } });
    await Document.deleteMany({ userId: userV1._id });
    console.log('✅ Database models validation and coexistence tests passed.\n');
  } catch (error) {
    console.error('❌ Test Case 3 Failed:', error.stack);
    // Cleanup anyway
    await User.deleteMany({ email: { $in: [testEmail, 'v2-test-temp-2@formos.online'] } });
    throw error;
  } finally {
    await mongoose.connection.close();
  }

  console.log('🎉 All Security V2 Foundation tests passed successfully!');
}

runTests()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('\n❌ Suite execution failed.');
    process.exit(1);
  });
