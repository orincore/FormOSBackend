require('dotenv').config({ path: __dirname + '/.env' });
const mongoose = require('mongoose');
const assert = require('assert');
const path = require('path');
const fs = require('fs/promises');
const Document = require('./models/Document');
const User = require('./models/User');
const StorageService = require('./services/storageService');
const { flags } = require('./config/featureFlags');
const { isS3Configured } = require('./services/s3Service');

// We simulate a mock multipart request to documentController.uploadDocument
const documentController = require('./controllers/documentController');

// Standard GCM File Envelope Helper (replaces client-side call in test space)
const createMockEnvelope = (content, filename, mimeType, version = 'formos_v2_file_aes_gcm', encVersion = 1, algorithm = 'AES-GCM') => {
  const headerJSON = JSON.stringify({
    v: version,
    encryptionVersion: encVersion,
    algorithm: algorithm,
    iv: 'dGVzdF9pdl9iYXNlNjQ=', // mock IV
    salt: 'dGVzdF9zYWx0X2Jhc2U2NA==', // mock salt
    wrappedKey: 'dGVzdF93cmFwcGVkX2tleV9iYXNlNjQ=', // mock wrapped DEK
    mimeType: mimeType
  });
  const headerBytes = Buffer.from(headerJSON, 'utf8');
  const ciphertextBytes = Buffer.from(content, 'utf8');
  
  const totalLength = 4 + headerBytes.length + ciphertextBytes.length;
  const envelope = Buffer.alloc(totalLength);
  
  envelope.writeUInt32BE(headerBytes.length, 0);
  headerBytes.copy(envelope, 4);
  ciphertextBytes.copy(envelope, 4 + headerBytes.length);
  
  return envelope;
};

// Mock Response object helper
const createMockResponse = () => {
  const res = {
    statusCode: 200,
    headers: {},
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(obj) {
      this.body = obj;
      return this;
    },
    send(data) {
      this.body = data;
      return this;
    },
    setHeader(name, val) {
      this.headers[name] = val;
      return this;
    }
  };
  return res;
};

async function runTests() {
  console.log('🧪 Starting Secure GridFS Storage Layer Tests...\n');

  // Connect to database
  const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/formos-test';
  await mongoose.connect(mongoUri);
  console.log('🔌 Connected to MongoDB.');

  // Clean up existing test database entries
  await User.deleteMany({ email: /test-storage-.*@example.com/ });
  await Document.deleteMany({ originalName: /encrypted_file|test-file/ });
  
  // Clean up GridFS collections
  const db = mongoose.connection.db;
  await db.collection('documents.files').deleteMany({});
  await db.collection('documents.chunks').deleteMany({});

  // Create V1 and V2 users
  const v1User = await User.create({
    email: 'test-storage-v1@example.com',
    name: 'V1 Storage User',
    password: 'password123',
    securityVersion: 1
  });

  const v2User = await User.create({
    email: 'test-storage-v2@example.com',
    name: 'V2 Storage User',
    password: 'password123',
    securityVersion: 2
  });

  // Enable feature flag temporarily
  flags.GRIDFS_ENABLED = true;

  console.log('🔍 Test Case 1: V2 upload/download round trip (stores opaque envelope)...');
  let v2DocId;
  const originalPlaintext = 'FormOS Cryptographic Vault Content 2026';
  try {
    const envelope = createMockEnvelope('SOME_ENCRYPTED_BINARY_NOISE_HERE', 'secrets.pdf', 'application/pdf');
    
    // Simulate upload
    const req = {
      userId: v2User._id,
      body: { documentType: 'aadhaar' },
      file: {
        buffer: envelope,
        originalname: 'secrets.pdf',
        mimetype: 'application/pdf',
        size: envelope.length
      }
    };
    const res = createMockResponse();

    await documentController.uploadDocument(req, res);
    assert.strictEqual(res.statusCode, 201, 'Upload status must be 201');
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.document.storageType, 'gridfs', 'Should use GridFS');
    assert.strictEqual(res.body.document.ocrStatus, 'skipped', 'Should skip server-side OCR');

    v2DocId = res.body.document.id;

    // Verify GridFS contents are strictly the encrypted envelope and NOT plaintext
    const dbDoc = await Document.findById(v2DocId);
    assert.ok(dbDoc.gridfsId, 'gridfsId must exist');
    assert.strictEqual(dbDoc.securityVersion, 2);
    assert.strictEqual(dbDoc.encryptionVersion, 1);
    
    const gridfsBytes = await StorageService.downloadFile(dbDoc);
    // GridFS should contain the exact same uploaded binary envelope
    assert.deepStrictEqual(gridfsBytes, envelope, 'GridFS must store the opaque client envelope');
    assert.ok(!gridfsBytes.toString().includes(originalPlaintext), 'Plaintext must not be directly readable');

    // Simulate download
    const downReq = {
      userId: v2User._id,
      params: { id: v2DocId }
    };
    const downRes = createMockResponse();
    await documentController.downloadDocument(downReq, downRes);

    assert.strictEqual(downRes.headers['Content-Type'], 'application/octet-stream', 'Should return octet-stream for client decryption');
    assert.deepStrictEqual(downRes.body, envelope, 'Downloaded payload must match envelope');

    console.log('✅ V2 upload/download round trip verified.');
  } catch (error) {
    console.error('❌ Test Case 1 Failed:', error);
    throw error;
  }

  console.log('\n🔍 Test Case 2: Verification of ownership checks (403 protection)...');
  try {
    // Attempt download of V2 document using V1 user credentials
    const unauthorizedReq = {
      userId: v1User._id,
      params: { id: v2DocId }
    };
    const unauthorizedRes = createMockResponse();
    await documentController.downloadDocument(unauthorizedReq, unauthorizedRes);

    assert.strictEqual(unauthorizedRes.statusCode, 404, 'Must return 404/Not Found or 403 to prevent discovery/access');
    console.log('✅ Ownership check verified (rejected unauthorized access).');
  } catch (error) {
    console.error('❌ Test Case 2 Failed:', error);
    throw error;
  }

  console.log('\n🔍 Test Case 3: V1 users blocked from the V2 storage path...');
  try {
    const envelope = createMockEnvelope('Some content', 'unauthorized.pdf', 'application/pdf');
    const req = {
      userId: v1User._id, // V1 user tries to upload V2 envelope
      body: { documentType: 'other' },
      file: {
        buffer: envelope,
        originalname: 'unauthorized.pdf',
        mimetype: 'application/pdf',
        size: envelope.length
      }
    };
    const res = createMockResponse();

    await documentController.uploadDocument(req, res);
    assert.strictEqual(res.statusCode, 403, 'Must reject with 403 Forbidden');
    assert.strictEqual(res.body.message.includes('V1 users are not allowed'), true);
    console.log('✅ V1 users blocked from V2 storage path successfully.');
  } catch (error) {
    console.error('❌ Test Case 3 Failed:', error);
    throw error;
  }

  console.log('\n🔍 Test Case 4: Malformed envelopes are rejected...');
  try {
    const malformedReq = {
      userId: v2User._id,
      body: { documentType: 'other' },
      file: {
        buffer: Buffer.from('NOT_A_VALID_V2_ENVELOPE_AT_ALL'),
        originalname: 'malformed.pdf',
        mimetype: 'application/pdf',
        size: 30
      }
    };
    const res = createMockResponse();

    await documentController.uploadDocument(malformedReq, res);
    // V2 user is not allowed to upload malformed plaintext
    assert.strictEqual(res.statusCode, 400, 'Must reject malformed file layout');
    assert.strictEqual(res.body.message.includes('must submit encrypted file envelopes'), true);
    console.log('✅ Malformed envelope rejection verified.');
  } catch (error) {
    console.error('❌ Test Case 4 Failed:', error);
    throw error;
  }

  console.log('\n🔍 Test Case 5: Unsupported encryptionVersion is rejected...');
  try {
    // Envelope version is formos_v2_file_aes_gcm but encryptionVersion = 999 (unsupported future version)
    const futureEnvelope = createMockEnvelope('Future Vault', 'future.pdf', 'application/pdf', 'formos_v2_file_aes_gcm', 999);
    const req = {
      userId: v2User._id,
      body: { documentType: 'other' },
      file: {
        buffer: futureEnvelope,
        originalname: 'future.pdf',
        mimetype: 'application/pdf',
        size: futureEnvelope.length
      }
    };
    const res = createMockResponse();

    await documentController.uploadDocument(req, res);
    assert.strictEqual(res.statusCode, 400, 'Must reject unsupported encryptionVersion');
    console.log('✅ Unsupported encryptionVersion rejection verified.');
  } catch (error) {
    console.error('❌ Test Case 5 Failed:', error);
    throw error;
  }

  console.log('\n🔍 Test Case 6: Failed DB operation cleans up GridFS (Transaction safety)...');
  try {
    const envelope = createMockEnvelope('Rollback content', 'rollback.pdf', 'application/pdf');
    const req = {
      userId: v2User._id,
      body: { documentType: 'INVALID_ENUM_TYPE_TO_FORCE_SCHEMA_VALIDATION_ERROR' },
      file: {
        buffer: envelope,
        originalname: 'rollback.pdf',
        mimetype: 'application/pdf',
        size: envelope.length
      }
    };
    const res = createMockResponse();

    await documentController.uploadDocument(req, res);

    assert.strictEqual(res.statusCode, 500, 'Must fail with validation error');
    
    // Ensure that no files are left in GridFS bucket.
    const db = mongoose.connection.db;
    const gridFiles = await db.collection('documents.files').find({ filename: 'encrypted_blob' }).toArray();
    
    // The rollback test case uploaded one file in TC 1, which succeeded.
    // So the total files should still be 1 (from TC 1), not 2!
    assert.strictEqual(gridFiles.length, 1, 'Dangling GridFS chunk was not deleted on DB failure');

    console.log('✅ Cleanup transaction verified (no orphaned files left).');
  } catch (error) {
    console.error('❌ Test Case 6 Failed:', error);
    throw error;
  }

  console.log('\n🔍 Test Case 7: Deleting a V2 document deletes GridFS object...');
  try {
    const delReq = {
      userId: v2User._id,
      params: { id: v2DocId }
    };
    const delRes = createMockResponse();
    await documentController.deleteDocument(delReq, delRes);

    assert.strictEqual(delRes.statusCode, 200);
    assert.strictEqual(delRes.body.success, true);

    // Verify Document collection has removed it
    const dbDoc = await Document.findById(v2DocId);
    assert.strictEqual(dbDoc, null, 'Document should be deleted from DB');

    // Verify GridFS bucket files are empty
    const db = mongoose.connection.db;
    const gridFiles = await db.collection('documents.files').find({ filename: 'encrypted_blob' }).toArray();
    assert.strictEqual(gridFiles.length, 0, 'GridFS file should be deleted');

    console.log('✅ Deletion of GridFS file on document delete verified.');
  } catch (error) {
    console.error('❌ Test Case 7 Failed:', error);
    throw error;
  }

  console.log('\n🔍 Test Case 8: V1 S3/local storage coexistence...');
  try {
    // V1 User uploads plaintext document
    const plaintext = 'Plaintext invoice content 2026';
    const req = {
      userId: v1User._id,
      body: { documentType: 'pan' },
      file: {
        buffer: Buffer.from(plaintext),
        originalname: 'invoice.pdf',
        mimetype: 'application/pdf',
        size: plaintext.length
      }
    };
    const res = createMockResponse();

    await documentController.uploadDocument(req, res);
    assert.strictEqual(res.statusCode, 201);
    const expectedStorageType = isS3Configured() ? 's3' : 'local';
    assert.strictEqual(res.body.document.storageType, expectedStorageType, `V1 should use ${expectedStorageType}`);

    const v1DocId = res.body.document.id;

    // Wait for background OCR processing to complete (avoids MongoNotConnectedError on exit)
    let dbDoc = await Document.findById(v1DocId);
    while (dbDoc.ocrStatus === 'pending' || dbDoc.ocrStatus === 'processing') {
      await new Promise((resolve) => setTimeout(resolve, 100));
      dbDoc = await Document.findById(v1DocId);
    }

    // Verify file exists and contains plaintext using StorageService abstraction
    assert.strictEqual(dbDoc.securityVersion, 1, 'Database securityVersion must be 1');
    assert.strictEqual(dbDoc.encryptionVersion, 0, 'Database encryptionVersion must be 0');
    const diskContent = await StorageService.downloadFile(dbDoc);
    assert.strictEqual(diskContent.toString(), plaintext, 'V1 storage must write unencrypted plaintext');

    // Cleanup V1 file
    await StorageService.deleteFile(dbDoc);
    await dbDoc.deleteOne();

    console.log('✅ V1 and V2 coexistence verified.');
  } catch (error) {
    console.error('❌ Test Case 8 Failed:', error);
    throw error;
  }

  // Cleanup Database users
  await v1User.deleteOne();
  await v2User.deleteOne();

  console.log('\n🎉 All Secure GridFS Storage Layer tests passed successfully!');
  await mongoose.disconnect();
}

runTests().catch((err) => {
  console.error('🛑 Test execution failed:', err);
  mongoose.disconnect();
  process.exit(1);
});
