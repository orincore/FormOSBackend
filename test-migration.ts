require('dotenv').config({ path: __dirname + '/.env' });
import assert from 'assert';
import mongoose from 'mongoose';
import { MigrationHelper, MigrationStatus } from '../FormOSFrontend/lib/security/migrationHelper';
import { deriveKeyFromPassword } from '../FormOSFrontend/lib/security/keyDerivation';
import { encryptFile, decryptFile } from '../FormOSFrontend/lib/security/fileEncryption';

const mockDB: {
  users: Record<string, any>;
  documents: Record<string, any>;
  gridfs: Record<string, Buffer>;
  s3: Record<string, Buffer>;
} = {
  users: {},
  documents: {},
  gridfs: {},
  s3: {}
};

const s3Service = require('./services/s3Service');
s3Service.downloadFromS3 = async (key: string) => {
  return mockDB.s3[key];
};
s3Service.deleteFromS3 = async (key: string) => {
  delete mockDB.s3[key];
};

const migrationController = require('./controllers/migrationController');
const documentController = require('./controllers/documentController');
const User = require('./models/User');
const Document = require('./models/Document');
const StorageService = require('./services/storageService');

const createMockResponse = () => {
  const res = {
    statusCode: 200,
    body: null as any,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(obj: any) {
      this.body = obj;
      return this;
    },
    send(data: any) {
      this.body = data;
      return this;
    },
    setHeader(name: string, value: string) {
      return this;
    }
  };
  return res;
};



// Override User and Document methods
const setupMockDB = () => {
  const s3Service = require('./services/s3Service');
  s3Service.downloadFromS3 = async (key: string) => {
    return mockDB.s3[key];
  };
  s3Service.deleteFromS3 = async (key: string) => {
    delete mockDB.s3[key];
  };

  User.findById = async (id: string) => mockDB.users[id] || null;
  User.findOne = async (query: any) => {
    if (query.email) {
      return Object.values(mockDB.users).find(u => u.email === query.email) || null;
    }
    return null;
  };
  Document.findOne = async (query: any) => {
    if (query._id) {
      return mockDB.documents[query._id] || null;
    }
    return null;
  };
  Document.countDocuments = async (query: any) => {
    return Object.values(mockDB.documents).filter(d => {
      let match = true;
      if (query.userId && d.userId !== query.userId) match = false;
      if (query.securityVersion !== undefined && d.securityVersion !== query.securityVersion) match = false;
      return match;
    }).length;
  };

  StorageService.uploadToGridFS = async (buffer: Buffer, filename: string, mimeType: string) => {
    const gridfsId = new mongoose.Types.ObjectId();
    mockDB.gridfs[gridfsId.toString()] = buffer;
    return gridfsId;
  };
  StorageService.downloadFile = async (doc: any) => {
    if (doc.storageType === 'gridfs') {
      return mockDB.gridfs[doc.gridfsId.toString()];
    } else if (doc.storageType === 's3') {
      return mockDB.s3[doc.s3Key];
    } else {
      return mockDB.s3[doc.filePath]; // local fallback mock
    }
  };
  StorageService.deleteFile = async (doc: any) => {
    if (doc.storageType === 's3' && doc.s3Key) {
      delete mockDB.s3[doc.s3Key];
    } else if (doc.storageType === 'local' && doc.filePath) {
      delete mockDB.s3[doc.filePath];
    }
  };
  StorageService.deleteFromGridFS = async (gridfsId: any) => {
    delete mockDB.gridfs[gridfsId.toString()];
  };
};

async function runTests() {
  console.log('🧪 Starting User V2 Security Migration System Tests...\n');
  setupMockDB();

  const migrationHelper = new MigrationHelper();

  // Test setup data
  const userId = 'user_migration_test_id';
  const pin = '123456';
  const v1UserDoc = {
    _id: userId,
    email: 'migration@example.com',
    name: 'V1 User',
    securityVersion: 1,
    migrationStatus: 'pending',
    extractedData: {
      fullName: 'V1 User',
      panNumber: 'ABCDE1234F',
      phone: '9876543210'
    },
    save() {
      mockDB.users[this._id] = this;
      return this;
    }
  };
  mockDB.users[userId] = v1UserDoc;

  // Documents
  const doc1 = {
    _id: 'doc1_id',
    userId,
    filename: 'resume.pdf',
    originalName: 'resume.pdf',
    filePath: 's3Key_resume',
    fileSize: 100,
    mimeType: 'application/pdf',
    storageType: 's3',
    s3Key: 's3Key_resume',
    securityVersion: 1,
    save() {
      mockDB.documents[this._id] = this;
      return this;
    }
  };
  const doc2 = {
    _id: 'doc2_id',
    userId,
    filename: 'id_card.png',
    originalName: 'id_card.png',
    filePath: 's3Key_idcard',
    fileSize: 200,
    mimeType: 'image/png',
    storageType: 's3',
    s3Key: 's3Key_idcard',
    securityVersion: 1,
    save() {
      mockDB.documents[this._id] = this;
      return this;
    }
  };
  doc1.save();
  doc2.save();

  // Add buffers in S3 mock
  mockDB.s3['s3Key_resume'] = Buffer.from('Mock PDF Content Bytes');
  mockDB.s3['s3Key_idcard'] = Buffer.from('Mock PNG Image Bytes');

  console.log('🔍 Test Case 1: Successful V2 Migration (Profile & all documents)...');
  try {
    // Implement mock API client callbacks matching MigrationHelper interface
    const callbacks = {
      downloadV1Document: async (id: string) => {
        const doc = mockDB.documents[id];
        const res = createMockResponse();
        const req = { userId, params: { id } };
        await documentController.downloadDocument(req, res);
        return new Blob([res.body]);
      },
      uploadV2Document: async (id: string, encryptedBlob: Blob) => {
        const buffer = Buffer.from(await encryptedBlob.arrayBuffer());
        const req = {
          userId,
          params: { id },
          file: { buffer, originalname: 'encrypted_file', mimetype: 'application/octet-stream' }
        };
        const res = createMockResponse();
        await migrationController.uploadDocumentMigration(req, res);
        assert.strictEqual(res.statusCode, 200);
        return { tempGridfsId: res.body.tempGridfsId };
      },
      downloadTempDocument: async (tempId: string) => {
        const req = { userId, params: { tempGridfsId: tempId } };
        const res = createMockResponse();
        await migrationController.downloadTempDocument(req, res);
        return new Blob([res.body]);
      },
      commitV2Document: async (id: string, tempId: string) => {
        const req = { userId, params: { id }, body: { tempGridfsId: tempId } };
        const res = createMockResponse();
        await migrationController.commitDocumentMigration(req, res);
        assert.strictEqual(res.statusCode, 200);
      },
      updateProfileMigration: async (payload: any) => {
        const req = { userId, body: payload };
        const res = createMockResponse();
        await migrationController.migrateProfile(req, res);
        assert.strictEqual(res.statusCode, 200);
      },
      completeMigration: async () => {
        const req = { userId };
        const res = createMockResponse();
        await migrationController.completeMigration(req, res);
        return res.body;
      },
      failMigration: async () => {
        const req = { userId };
        const res = createMockResponse();
        await migrationController.failMigration(req, res);
      }
    };

    // Run migration
    const documentList = [doc1, doc2];
    await migrationHelper.runMigration(pin, v1UserDoc.extractedData, documentList, callbacks);

    // Assert successful completion
    const migratedUser = mockDB.users[userId];
    assert.strictEqual(migratedUser.securityVersion, 2);
    assert.strictEqual(migratedUser.migrationStatus, 'completed');
    assert.deepStrictEqual(migratedUser.extractedData, {}); // Plaintext cleared

    // Assert documents migrated
    assert.strictEqual(mockDB.documents['doc1_id'].securityVersion, 2);
    assert.strictEqual(mockDB.documents['doc1_id'].storageType, 'gridfs');
    assert.strictEqual(mockDB.documents['doc2_id'].securityVersion, 2);

    // Verify legacy S3 files deleted
    assert.strictEqual(mockDB.s3['s3Key_resume'], undefined);
    assert.strictEqual(mockDB.s3['s3Key_idcard'], undefined);

    console.log('✅ Successful migration verified.');
  } catch (error) {
    console.error('❌ Test Case 1 Failed:', error);
    throw error;
  }

  console.log('\n🔍 Test Case 2: Interrupted / Resumed Migration & Idempotency...');
  try {
    // Reset DB to V1
    v1UserDoc.securityVersion = 1;
    v1UserDoc.migrationStatus = 'pending';
    v1UserDoc.extractedData = { fullName: 'V1 User', panNumber: 'ABCDE1234F', phone: '9876543210' };
    mockDB.s3['s3Key_resume'] = Buffer.from('Mock PDF Content Bytes');
    mockDB.s3['s3Key_idcard'] = Buffer.from('Mock PNG Image Bytes');
    doc1.securityVersion = 1;
    doc1.storageType = 's3';
    doc2.securityVersion = 1;
    doc2.storageType = 's3';

    let failOnDoc2 = true;

    const callbacks = {
      downloadV1Document: async (id: string) => {
        return new Blob([mockDB.s3[mockDB.documents[id].s3Key] as any]);
      },
      uploadV2Document: async (id: string, encryptedBlob: Blob) => {
        if (id === 'doc2_id' && failOnDoc2) {
          throw new Error('Simulated network interruption on uploading doc2');
        }
        const buffer = Buffer.from(await encryptedBlob.arrayBuffer());
        const req = {
          userId,
          params: { id },
          file: { buffer, originalname: 'encrypted_file', mimetype: 'application/octet-stream' }
        };
        const res = createMockResponse();
        await migrationController.uploadDocumentMigration(req, res);
        return { tempGridfsId: res.body.tempGridfsId };
      },
      downloadTempDocument: async (tempId: string) => {
        return new Blob([mockDB.gridfs[tempId] as any]);
      },
      commitV2Document: async (id: string, tempId: string) => {
        const req = { userId, params: { id }, body: { tempGridfsId: tempId } };
        const res = createMockResponse();
        await migrationController.commitDocumentMigration(req, res);
      },
      updateProfileMigration: async (payload: any) => {
        const req = { userId, body: payload };
        const res = createMockResponse();
        await migrationController.migrateProfile(req, res);
      },
      completeMigration: async () => {
        const req = { userId };
        const res = createMockResponse();
        await migrationController.completeMigration(req, res);
        return res.body;
      },
      failMigration: async () => {
        const req = { userId };
        const res = createMockResponse();
        await migrationController.failMigration(req, res);
      }
    };

    // First attempt: should fail on doc2
    try {
      await migrationHelper.runMigration(pin, v1UserDoc.extractedData, [doc1, doc2], callbacks);
      assert.fail('Migration should have thrown an error');
    } catch (err: any) {
      assert.ok(err.message.includes('Simulated network interruption'));
    }

    // Verify DB states after interruption
    const userState = mockDB.users[userId];
    assert.strictEqual(userState.migrationStatus, 'failed');
    assert.strictEqual(userState.securityVersion, 1); // Remains V1
    assert.strictEqual(mockDB.documents['doc1_id'].securityVersion, 2); // doc1 migrated
    assert.strictEqual(mockDB.documents['doc2_id'].securityVersion, 1); // doc2 not migrated
    assert.ok(mockDB.s3['s3Key_idcard'], 'doc2 plaintext is NOT deleted');

    // Second attempt: retry (resume)
    failOnDoc2 = false;
    await migrationHelper.runMigration(pin, v1UserDoc.extractedData, [doc1, doc2], callbacks);

    // Verify final state
    assert.strictEqual(userState.migrationStatus, 'completed');
    assert.strictEqual(userState.securityVersion, 2);
    assert.strictEqual(mockDB.documents['doc2_id'].securityVersion, 2);
    assert.strictEqual(mockDB.s3['s3Key_idcard'], undefined, 'doc2 plaintext deleted after retry success');

    console.log('✅ Interrupted / Resumed Migration verified (idempotent document skips).');
  } catch (error) {
    console.error('❌ Test Case 2 Failed:', error);
    throw error;
  }

  console.log('\n🔍 Test Case 3: Failed Profile Encryption/Verification rollback...');
  try {
    v1UserDoc.securityVersion = 1;
    v1UserDoc.migrationStatus = 'pending';

    const callbacks = {
      downloadV1Document: async (id: string) => new Blob(),
      uploadV2Document: async (id: string, encryptedBlob: Blob) => ({ tempGridfsId: 'mock' }),
      downloadTempDocument: async (tempId: string) => new Blob(),
      commitV2Document: async (id: string, tempId: string) => {},
      updateProfileMigration: async (payload: any) => {
        // Simulating bad upload / failure
        throw new Error('Simulated payload upload error');
      },
      completeMigration: async () => ({ migrationStatus: 'failed' }),
      failMigration: async () => {
        const req = { userId };
        const res = createMockResponse();
        await migrationController.failMigration(req, res);
      }
    };

    try {
      await migrationHelper.runMigration(pin, v1UserDoc.extractedData, [], callbacks);
      assert.fail('Should have failed');
    } catch (err: any) {
      assert.strictEqual(mockDB.users[userId].migrationStatus, 'failed');
      assert.strictEqual(mockDB.users[userId].securityVersion, 1);
    }
    console.log('✅ Failed Profile Encryption verified.');
  } catch (error) {
    console.error('❌ Test Case 3 Failed:', error);
    throw error;
  }

  console.log('\n🔍 Test Case 4: V1 User Continuing Normally (Before/No Migration)...');
  try {
    const User = require('./models/User');
    const originalFindById = User.findById;
    
    // Mock user context as V1
    const v1UserObj = { _id: 'v1_user_active', securityVersion: 1, extractedData: { fullName: 'V1 User Name' } };
    User.findById = async () => v1UserObj;

    const authController = require('./controllers/authController');
    
    // Call reveal profile
    const req = { userId: 'v1_user_active', user: v1UserObj };
    const res = createMockResponse();
    await authController.getFullProfile(req, res);
    
    // Restore
    User.findById = originalFindById;

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.user.extractedData.fullName, 'V1 User Name', 'V1 user must retrieve plaintext profile data');
    console.log('✅ V1 normal operations verified.');
  } catch (error) {
    console.error('❌ Test Case 4 Failed:', error);
    throw error;
  }

  console.log('\n🔍 Test Case 5: V2 User Continuing Normally (After Successful Migration)...');
  try {
    const User = require('./models/User');
    const originalFindById = User.findById;
    
    // Mock user context as V2
    const v2UserObj = { _id: 'v2_user_active', securityVersion: 2, encryptedProfile: 'v2_encrypted_blob' };
    User.findById = async () => v2UserObj;

    const authController = require('./controllers/authController');
    const autofillController = require('./controllers/autofillController');

    // Call reveal profile
    const profileReq = { userId: 'v2_user_active', user: v2UserObj };
    const profileRes = createMockResponse();
    await authController.getFullProfile(profileReq, profileRes);

    // Call legacy V1 autofill endpoint -> must reject
    const autofillReq = { userId: 'v2_user_active', query: {} };
    const autofillRes = createMockResponse();
    await autofillController.getAutofillData(autofillReq, autofillRes);

    // Restore
    User.findById = originalFindById;

    assert.strictEqual(profileRes.statusCode, 200);
    assert.strictEqual(profileRes.body.user.extractedData.fullName, undefined, 'V2 user must not get plaintext profile');
    assert.strictEqual(profileRes.body.user.encryptedProfile, 'v2_encrypted_blob', 'V2 user must receive encrypted profile');
    assert.strictEqual(autofillRes.statusCode, 403, 'V2 user must be blocked from legacy plaintext autofill');

    console.log('✅ V2 normal operations verified.');
  } catch (error) {
    console.error('❌ Test Case 5 Failed:', error);
    throw error;
  }

  console.log('\n🎉 All User Migration tests passed successfully!');
}

runTests()
  .then(() => process.exit(0))
  .catch(() => process.exit(1));
