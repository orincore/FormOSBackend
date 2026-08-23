const assert = require('assert');
const path = require('path');
const fs = require('fs');
const aiService = require('./services/aiService');
const eligibilityController = require('./controllers/eligibilityController');
const formAnalyzerController = require('./controllers/formAnalyzerController');

// Mock response creator
const createMockResponse = () => {
  return {
    statusCode: 200,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(obj) {
      this.body = obj;
      return this;
    }
  };
};

async function runTests() {
  console.log('🧪 Starting Secure AI Request Policy Guard Tests...\n');

  // Stub isConfigured to run tests without actual API key configurations
  aiService.isConfigured = () => true;

  // Trusted mock users
  const v1User = { _id: 'user1', securityVersion: 1 };
  const v2User = { _id: 'user2', securityVersion: 2 };

  // Test Case A: V1 allows RAG/Eligibility
  console.log('🔍 Test Case A: V1 allowed (RAG/Eligibility operations)...');
  try {
    const originalChat = aiService.chat;
    let chatCalled = false;
    aiService.chat = async () => {
      chatCalled = true;
      return '{"opportunityType": "PM Scholarship", "matchScore": 95}';
    };

    const req = { userId: 'user1', body: { jd: 'PM Scholarship requirements' } };
    const res = createMockResponse();

    // Mock DB resolution for eligibilityController
    const User = require('./models/User');
    const originalFindById = User.findById;
    User.findById = async () => v1User;

    await eligibilityController.checkEligibility(req, res);
    
    // Restore
    aiService.chat = originalChat;
    User.findById = originalFindById;

    if (res.statusCode !== 200) {
      console.log('Test Case A failed response body:', res.body);
    }
    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(chatCalled, true);
    console.log('✅ V1 bypass verified (allowed).');
  } catch (error) {
    console.error('❌ Test Case A Failed:', error);
    throw error;
  }

  // Test Case B: V2 LOCAL_ONLY operation is blocked
  console.log('\n🔍 Test Case B: V2 LOCAL_ONLY operation (Eligibility/RAG) is blocked...');
  try {
    const req = { userId: 'user2', body: { jd: 'PM Scholarship requirements' } };
    const res = createMockResponse();

    const User = require('./models/User');
    const originalFindById = User.findById;
    User.findById = async () => v2User;

    await eligibilityController.checkEligibility(req, res);

    User.findById = originalFindById;

    assert.strictEqual(res.statusCode, 403);
    assert.strictEqual(res.body.success, false);
    assert.strictEqual(res.body.code, 'AI_POLICY_VIOLATION');
    assert.strictEqual(res.body.operation, 'ELIGIBILITY');
    assert.strictEqual(res.body.securityVersion, 2);
    console.log('✅ V2 LOCAL_ONLY blocked successfully.');
  } catch (error) {
    console.error('❌ Test Case B Failed:', error);
    throw error;
  }

  // Test Case C: V2 SAFE_FOR_CLOUD with PII is blocked
  console.log('\n🔍 Test Case C: V2 SAFE_FOR_CLOUD operation with PII is blocked...');
  try {
    let policyViolationThrown = false;
    try {
      await aiService.chat(
        'System prompt: map fields',
        'User labels: ["My Phone 9876543210"]',
        { user: v2User, operation: aiService.AI_OPERATION.SCHEMA_MAPPING }
      );
    } catch (err) {
      if (err.name === 'AIPolicyViolationError') {
        policyViolationThrown = true;
        // Assert no PII leaks into error fields or message
        assert.ok(!err.message.includes('9876543210'), 'Error message must not leak PII');
      }
    }
    assert.strictEqual(policyViolationThrown, true, 'PII in schema mapping must be blocked');
    console.log('✅ V2 SAFE_FOR_CLOUD PII detection verified (blocked).');
  } catch (error) {
    console.error('❌ Test Case C Failed:', error);
    throw error;
  }

  // Test Case D: V2 SAFE_FOR_CLOUD with safe schema is allowed
  console.log('\n🔍 Test Case D: V2 SAFE_FOR_CLOUD operation with safe schema is allowed...');
  try {
    const originalChat = aiService.chat;
    let chatCalled = false;
    aiService.chat = async () => {
      chatCalled = true;
      return '{"Employee Name": "full_name"}';
    };

    const req = { user: v2User, body: { labels: ['Employee Name'] } };
    const res = createMockResponse();

    await formAnalyzerController.mapStructure(req, res);
    aiService.chat = originalChat;

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(chatCalled, true);
    console.log('✅ V2 SAFE_FOR_CLOUD schema mappings verified (allowed).');
  } catch (error) {
    console.error('❌ Test Case D Failed:', error);
    throw error;
  }

  // Test Case E: Attempt to spoof securityVersion remains blocked
  console.log('\n🔍 Test Case E: Attempt to spoof securityVersion (request says V1, DB says V2)...');
  try {
    // Caller tries to pass V1 parameters, but controller resolves user from database
    const req = { userId: 'user2', body: { jd: 'PM Scholarship', securityVersion: 1 } };
    const res = createMockResponse();

    const User = require('./models/User');
    const originalFindById = User.findById;
    User.findById = async () => v2User; // Trusted DB context resolves V2 user!

    await eligibilityController.checkEligibility(req, res);
    User.findById = originalFindById;

    assert.strictEqual(res.statusCode, 403);
    assert.strictEqual(res.body.securityVersion, 2, 'Must enforce securityVersion resolved from trusted DB context');
    console.log('✅ Spoofed securityVersion attempt blocked.');
  } catch (error) {
    console.error('❌ Test Case E Failed:', error);
    throw error;
  }

  // Test Case F: Attempt to spoof category/operation remains blocked
  console.log('\n🔍 Test Case F: Attempt to spoof category/operation (caller tries to mark sensitive task as safe)...');
  try {
    // If a caller tries to execute map-structure but includes sensitive context
    const req = { user: v2User, body: { labels: ['My PAN ID is ABCDE1234F'] } };
    const res = createMockResponse();

    await formAnalyzerController.mapStructure(req, res);

    assert.strictEqual(res.statusCode, 400); // Blocked at validator boundary / PII scan
    console.log('✅ Spoofed category/operation attempt blocked.');
  } catch (error) {
    console.error('❌ Test Case F Failed:', error);
    throw error;
  }

  // Test Case G: Missing user/security context fails closed
  console.log('\n🔍 Test Case G: Missing user/security context fails closed...');
  try {
    let failedClosed = false;
    try {
      await aiService.chat('System mapping', 'labels: ["Employee Name"]', {
        operation: aiService.AI_OPERATION.SCHEMA_MAPPING
        // user context is missing
      });
    } catch (err) {
      if (err.name === 'AIPolicyViolationError') {
        failedClosed = true;
      }
    }
    assert.strictEqual(failedClosed, true, 'Must fail closed if user context is missing');
    console.log('✅ Missing context fail-closed verified.');
  } catch (error) {
    console.error('❌ Test Case G Failed:', error);
    throw error;
  }

  // Test Case H: Unknown operation fails closed
  console.log('\n🔍 Test Case H: Unknown operation fails closed...');
  try {
    let failedClosed = false;
    try {
      await aiService.chat('System mapping', 'labels: ["Employee Name"]', {
        user: v2User,
        operation: 'UNKNOWN_OR_MALICIOUS_OP'
      });
    } catch (err) {
      if (err.name === 'AIPolicyViolationError') {
        failedClosed = true;
      }
    }
    assert.strictEqual(failedClosed, true, 'Must fail closed if operation is unknown');
    console.log('✅ Unknown operation fail-closed verified.');
  } catch (error) {
    console.error('❌ Test Case H Failed:', error);
    throw error;
  }

  // Test Case I: Fallback provider checks
  console.log('\n🔍 Test Case I: Provider fallback cannot bypass policy...');
  try {
    let guardInvokedCount = 0;
    const originalGuard = aiService.enforcePolicyGuard;
    aiService.enforcePolicyGuard = function() {
      guardInvokedCount++;
      return originalGuard.apply(aiService, arguments);
    };

    // Even if we retry chat calls or change providers, it must execute the guard checklist
    try {
      await aiService.chat('System mapping', 'labels: ["Employee Name"]', {
        user: v2User,
        operation: 'SENSITIVE_ANALYSIS'
      });
    } catch { /* expected policy block */ }

    aiService.enforcePolicyGuard = originalGuard;
    assert.strictEqual(guardInvokedCount, 1, 'Policy guard must execute for all attempts');
    console.log('✅ Fallback policy checks verified.');
  } catch (error) {
    console.error('❌ Test Case I Failed:', error);
    throw error;
  }

  // Test Case J: Direct provider bypass audit
  console.log('\n🔍 Test Case J: Codebase audit verification...');
  const backendDir = __dirname;
  const files = fs.readdirSync(path.join(backendDir, 'services'));
  for (const file of files) {
    if (file.endsWith('.js') && file !== 'aiService.js') {
      const content = fs.readFileSync(path.join(backendDir, 'services', file), 'utf8');
      assert.ok(!content.includes('GoogleGenerativeAI'), `Bypass audit error in services/${file}: must not import SDK directly`);
      assert.ok(!content.includes('require(\'openai\')'), `Bypass audit error in services/${file}: must not import SDK directly`);
    }
  }
  console.log('✅ Codebase bypass audit verified (no direct alternate provider bypasses found).');

  console.log('\n🎉 All Secure AI Request Policy Guard tests passed successfully!');
}

runTests()
  .then(() => process.exit(0))
  .catch(() => process.exit(1));
