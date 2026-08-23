require('dotenv').config({ path: __dirname + '/.env' });
import assert from 'assert';

const mockDB: {
  users: Record<string, any>;
  documents: Record<string, any>;
  s3: Record<string, Buffer>;
} = {
  users: {},
  documents: {},
  s3: {}
};

// Mock s3Service
const s3Service = require('./services/s3Service');
s3Service.downloadFromS3 = async (key: string) => mockDB.s3[key];
s3Service.deleteFromS3 = async (key: string) => { delete mockDB.s3[key]; };

const User = require('./models/User');
const Document = require('./models/Document');
const aiService = require('./services/aiService');
const ragService = require('./services/ragService');
const documentController = require('./controllers/documentController');
const chatController = require('./controllers/chatController');
const eligibilityController = require('./controllers/eligibilityController');

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

// Mock database methods
const makeMockUser = (userObj: any) => {
  if (!userObj) return null;
  return {
    ...userObj,
    async save() {
      // Sync properties back to mockDB
      Object.assign(mockDB.users[this._id], this);
      return this;
    }
  };
};

User.findById = async (id: string) => makeMockUser(mockDB.users[id]);
User.findByIdAndUpdate = async (id: string, update: any) => {
  const user = mockDB.users[id];
  if (user) {
    Object.assign(user, update);
    return makeMockUser(user);
  }
  return null;
};
Document.findOne = async (query: any) => {
  if (query._id) {
    const doc = mockDB.documents[query._id];
    if (doc && query.userId && doc.userId !== query.userId) {
      return null; // Enforce ownership verification
    }
    return doc || null;
  }
  return null;
};
Document.find = (query: any) => {
  const chain = {
    sort() { return this; },
    limit() { return this; },
    select() { return this; },
    then(onResolve: any) {
      const results = Object.values(mockDB.documents).filter((d: any) => {
        let match = true;
        if (query.userId && d.userId !== query.userId) match = false;
        if (query.ocrStatus && d.ocrStatus !== query.ocrStatus) match = false;
        return match;
      });
      return Promise.resolve(onResolve(results));
    }
  };
  return chain as any;
};
Document.findOneAndUpdate = async (query: any, update: any, options: any) => {
  const doc = await Document.findOne(query);
  if (doc) {
    Object.assign(doc, update);
    return doc;
  }
  return null;
};
Document.findByIdAndUpdate = async (id: string, update: any, options: any) => {
  const doc = mockDB.documents[id];
  if (doc) {
    Object.assign(doc, update);
    return doc;
  }
  return null;
};

async function runTests() {
  console.log('🧪 Starting Security V2 RAG and Document Protection Tests...\n');

  // Seed Users
  const v1UserId = 'v1_user';
  const v2UserId = 'v2_user';
  const hackerUserId = 'hacker_user';

  mockDB.users[v1UserId] = {
    _id: v1UserId,
    securityVersion: 1,
    extractedData: { fullName: 'V1 User Profile Name', aadhaarNumber: '123456789012' }
  };

  mockDB.users[v2UserId] = {
    _id: v2UserId,
    securityVersion: 2,
    encryptedProfile: JSON.stringify({ iv: 'mock', ct: 'mock', v: 'formos_v2_aes_gcm_pbkdf2' }),
    userSalt: 'mock_salt',
    wrappedUserKey: 'mock_wrapped_key',
    extractedData: {} // Empty on server under V2
  };

  mockDB.users[hackerUserId] = {
    _id: hackerUserId,
    securityVersion: 2,
    extractedData: {}
  };

  // Seed Documents
  const v1DocId = 'v1_doc';
  const v2DocId = 'v2_doc';

  mockDB.documents[v1DocId] = {
    _id: v1DocId,
    userId: v1UserId,
    securityVersion: 1,
    originalName: 'v1_resume.pdf',
    storageType: 's3',
    ocrStatus: 'completed',
    extractedText: 'V1 resume text content containing sensitive info',
    structuredData: { phone: '9876543210' }
  };

  mockDB.documents[v2DocId] = {
    _id: v2DocId,
    userId: v2UserId,
    securityVersion: 2,
    originalName: 'encrypted_file',
    storageType: 'gridfs',
    ocrStatus: 'completed',
    encryptedText: JSON.stringify({ iv: 'mock', ct: 'mock_text', v: 'formos_v2_aes_gcm_pbkdf2' }),
    encryptedStructuredData: JSON.stringify({ iv: 'mock', ct: 'mock_struct', v: 'formos_v2_aes_gcm_pbkdf2' }),
    extractedText: '', // Empty on server for V2
    structuredData: {}
  };

  // ==========================================
  // V1 Compatibility Tests
  // ==========================================
  console.log('🔍 Test Case 1: V1 chat/RAG continues working...');
  try {
    const originalChat = aiService.chat;
    let chatCalled = false;
    aiService.chat = async (sys: string, user: string, options: any) => {
      chatCalled = true;
      assert.strictEqual(options.operation, 'RAG');
      assert.strictEqual(options.user.securityVersion, 1);
      return 'Mock V1 AI Answer';
    };

    const req = { userId: v1UserId, body: { message: 'Is there a visa document in my profile?' } };
    const res = createMockResponse();
    await chatController.chat(req, res);

    aiService.chat = originalChat;

    assert.strictEqual(res.statusCode, 200);
    assert.ok(chatCalled, 'Should invoke Cloud AI for V1 user');
    console.log('✅ V1 chat/RAG compatibility verified.');
  } catch (err) {
    console.error('❌ Test Case 1 Failed:', err);
    throw err;
  }

  console.log('\n🔍 Test Case 2: V1 document serialization and update remains compatible...');
  try {
    // Retrieval path
    const getReq = { userId: v1UserId, params: { id: v1DocId } };
    const getRes = createMockResponse();
    await documentController.getDocument(getReq, getRes);

    assert.strictEqual(getRes.statusCode, 200);
    assert.strictEqual(getRes.body.document.encryptedText, undefined);
    assert.strictEqual(getRes.body.document.securityVersion, 1);

    // Update path
    const updateReq = {
      userId: v1UserId,
      params: { id: v1DocId },
      body: { structuredData: { phone: '1111111111' } }
    };
    const updateRes = createMockResponse();
    await documentController.updateStructuredData(updateReq, updateRes);

    assert.strictEqual(updateRes.statusCode, 200);
    assert.strictEqual(mockDB.documents[v1DocId].structuredData.phone, '1111111111');
    assert.strictEqual(mockDB.users[v1UserId].extractedData.phone, '1111111111');
    console.log('✅ V1 document operations verified.');
  } catch (err) {
    console.error('❌ Test Case 2 Failed:', err);
    throw err;
  }

  // ==========================================
  // V2 Security Protection Tests
  // ==========================================
  console.log('\n🔍 Test Case 3: Server-side RAG is blocked (fails closed) for V2...');
  try {
    const req = { userId: v2UserId, body: { message: 'What is my Aadhaar?' } };
    const res = createMockResponse();
    await chatController.chat(req, res);

    assert.strictEqual(res.statusCode, 403);
    assert.strictEqual(res.body.code, 'AI_POLICY_VIOLATION');
    console.log('✅ Server-side V2 RAG fail-closed verified.');
  } catch (err) {
    console.error('❌ Test Case 3 Failed:', err);
    throw err;
  }

  console.log('\n🔍 Test Case 4: Indirect Cloud-AI / Eligibility invocation is blocked for V2...');
  try {
    const req = { userId: v2UserId, body: { jd: 'Must have Aadhaar card' } };
    const res = createMockResponse();
    await eligibilityController.checkEligibility(req, res);

    assert.strictEqual(res.statusCode, 403);
    assert.strictEqual(res.body.code, 'AI_POLICY_VIOLATION');
    console.log('✅ Server-side V2 Eligibility fail-closed verified.');
  } catch (err) {
    console.error('❌ Test Case 4 Failed:', err);
    throw err;
  }

  console.log('\n🔍 Test Case 5: V2 document retrieval returns ciphertext only (no keys or plaintext)...');
  try {
    const req = { userId: v2UserId, params: { id: v2DocId } };
    const res = createMockResponse();
    await documentController.getSecureV2Document(req, res);

    assert.strictEqual(res.statusCode, 200);
    assert.ok(res.body.document.encryptedText);
    assert.ok(res.body.document.encryptedStructuredData);
    assert.strictEqual(res.body.document.extractedText, undefined);
    assert.strictEqual(res.body.document.structuredData, undefined);
    console.log('✅ V2 secure document retrieval verified.');
  } catch (err) {
    console.error('❌ Test Case 5 Failed:', err);
    throw err;
  }

  console.log('\n🔍 Test Case 6: Unauthorized users cannot retrieve another user\'s V2 documents...');
  try {
    const req = { userId: hackerUserId, params: { id: v2DocId } };
    const res = createMockResponse();
    await documentController.getSecureV2Document(req, res);

    // Should return 404 since Document.findOne query constraints filter by userId
    assert.strictEqual(res.statusCode, 404);
    console.log('✅ V2 document authorization boundary verified.');
  } catch (err) {
    console.error('❌ Test Case 6 Failed:', err);
    throw err;
  }

  console.log('\n🔍 Test Case 7: V2 encrypted document updates work and preserve V1 contract...');
  try {
    const req = {
      userId: v2UserId,
      params: { id: v2DocId },
      body: {
        encryptedText: 'updated_ciphertext_text',
        encryptedStructuredData: 'updated_ciphertext_struct'
      }
    };
    const res = createMockResponse();
    await documentController.updateSecureV2Document(req, res);

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(mockDB.documents[v2DocId].encryptedText, 'updated_ciphertext_text');
    assert.strictEqual(mockDB.documents[v2DocId].encryptedStructuredData, 'updated_ciphertext_struct');
    assert.strictEqual(mockDB.documents[v2DocId].extractedText, ''); // Ensure plaintext text is not populated
    console.log('✅ V2 document secure update verified.');
  } catch (err) {
    console.error('❌ Test Case 7 Failed:', err);
    throw err;
  }

  console.log('\n🔍 Test Case 8: V2 document storage fallback safeguard blocks S3 fallback...');
  try {
    const StorageService = require('./services/storageService');
    const badDoc = {
      _id: 'bad_v2_doc',
      userId: v2UserId,
      securityVersion: 2,
      storageType: 's3',
      s3Key: 'some_key'
    };

    try {
      await StorageService.downloadFile(badDoc);
      assert.fail('Should have blocked download fallback');
    } catch (err: any) {
      assert.ok(err.message.includes('Security Violation'), 'Should throw Security Violation error');
    }

    try {
      await StorageService.deleteFile(badDoc);
      assert.fail('Should have blocked delete fallback');
    } catch (err: any) {
      assert.ok(err.message.includes('Security Violation'), 'Should throw Security Violation error');
    }

    console.log('✅ Storage fallback safeguards verified successfully.');
  } catch (err) {
    console.error('❌ Test Case 8 Failed:', err);
    throw err;
  }

  console.log('\n🎉 All RAG and Document V2 Security tests passed successfully!');
}

runTests()
  .then(() => process.exit(0))
  .catch(() => process.exit(1));
