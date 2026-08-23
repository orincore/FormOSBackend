require('dotenv').config({ path: __dirname + '/.env' });
import mongoose from 'mongoose';
import assert from 'assert';
import { LocalProcessor } from '../FormOSFrontend/lib/security/localProcessor';

// We simulate mock request/response to test map-structure backend controller
const formAnalyzerController = require('./controllers/formAnalyzerController');
const aiService = require('./services/aiService');

// Mock response creator
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
    }
  };
  return res;
};

async function runTests() {
  console.log('🧪 Starting Secure Document Processing Pipeline Tests...\n');

  const localProcessor = new LocalProcessor();

  console.log('🔍 Test Case 1: Client-Side localProcessor Segregation & Sanitization...');
  try {
    // 1.1 "Employee Name: Tanya Jha"
    const text1 = 'Employee Name: Tanya Jha';
    const res1 = await localProcessor.processDocumentText(text1);
    assert.strictEqual(res1.safeLabels.length, 1);
    assert.strictEqual(res1.safeLabels[0], 'Employee Name');
    // Ensure value is separated and kept locally
    const seg1 = res1.allSegments.find(s => s.label === 'Employee Name')!;
    assert.strictEqual(seg1.value, 'Tanya Jha');
    assert.strictEqual(seg1.safeForCloud, true);

    // 1.2 "PAN: ABCDE1234F"
    const text2 = 'PAN: ABCDE1234F';
    const res2 = await localProcessor.processDocumentText(text2);
    assert.strictEqual(res2.safeLabels[0], 'PAN');
    const seg2 = res2.allSegments.find(s => s.label === 'PAN')!;
    assert.strictEqual(seg2.value, 'ABCDE1234F');
    assert.strictEqual(seg2.safeForCloud, true);

    // 1.3 "Phone: 9876543210"
    const text3 = 'Phone: 9876543210';
    const res3 = await localProcessor.processDocumentText(text3);
    assert.strictEqual(res3.safeLabels[0], 'Phone');
    const seg3 = res3.allSegments.find(s => s.label === 'Phone')!;
    assert.strictEqual(seg3.value, '9876543210');
    assert.strictEqual(seg3.safeForCloud, true);

    // 1.4 "Email: test@example.com"
    const text4 = 'Email: test@example.com';
    const res4 = await localProcessor.processDocumentText(text4);
    assert.strictEqual(res4.safeLabels[0], 'Email');
    const seg4 = res4.allSegments.find(s => s.label === 'Email')!;
    assert.strictEqual(seg4.value, 'test@example.com');
    assert.strictEqual(seg4.safeForCloud, true);

    console.log('✅ Client-side label/value segregation verified.');
  } catch (error) {
    console.error('❌ Test Case 1 Failed:', error);
    throw error;
  }

  console.log('\n🔍 Test Case 2: Fail-Closed segments logic (Name Tanya Jha Employee ID EMP12345)...');
  try {
    const text = 'Name Tanya Jha Employee ID EMP12345';
    const res = await localProcessor.processDocumentText(text);
    // Since there is no clear boundary separator, the segment must fail closed
    assert.strictEqual(res.safeLabels.length, 0, 'Must not send labels to cloud for uncertain segments');
    assert.strictEqual(res.allSegments[0].safeForCloud, false);
    assert.strictEqual(res.allSegments[0].value, text, 'Complete segment must remain local');
    console.log('✅ Fail-closed segment isolation verified.');
  } catch (error) {
    console.error('❌ Test Case 2 Failed:', error);
    throw error;
  }

  console.log('\n🔍 Test Case 3: Secondary Defense Validator boundary checks (Backend endpoint)...');
  try {
    // 3.1 Rejected: Email
    const req1 = { body: { labels: ['Candidate Email', 'test@example.com'] } };
    const res1 = createMockResponse();
    await formAnalyzerController.mapStructure(req1, res1);
    assert.strictEqual(res1.statusCode, 400);
    assert.strictEqual(res1.body.success, false);
    assert.ok(res1.body.message.includes('Potential sensitive data detected'), 'Should detect email PII');

    // 3.2 Rejected: Phone
    const req2 = { body: { labels: ['Mobile Number', '+12345678901'] } };
    const res2 = createMockResponse();
    await formAnalyzerController.mapStructure(req2, res2);
    assert.strictEqual(res2.statusCode, 400);
    assert.ok(res2.body.message.includes('Potential sensitive data detected'), 'Should detect phone PII');

    // 3.3 Rejected: PAN-like ID
    const req3 = { body: { labels: ['PAN', 'ABCDE1234F'] } };
    const res3 = createMockResponse();
    await formAnalyzerController.mapStructure(req3, res3);
    assert.strictEqual(res3.statusCode, 400);
    assert.ok(res3.body.message.includes('Potential sensitive data detected'), 'Should detect PAN PII');

    // 3.4 Rejected: Too long label
    const req4 = { body: { labels: ['A'.repeat(51)] } };
    const res4 = createMockResponse();
    await formAnalyzerController.mapStructure(req4, res4);
    assert.strictEqual(res4.statusCode, 400);
    assert.ok(res4.body.message.includes('Label exceeds maximum length'), 'Should reject too long labels');

    // 3.5 Allowed: Legit number/year label
    const req5 = { body: { labels: ['Form 2026', 'Tax Year 2025'] } };
    const res5 = createMockResponse();
    // Stub the AI chat call to prevent making actual remote API calls during validation tests
    const originalChat = aiService.chat;
    aiService.chat = async () => '{"Form 2026": null, "Tax Year 2025": null}';
    
    await formAnalyzerController.mapStructure(req5, res5);
    // Restore original chat
    aiService.chat = originalChat;
    
    assert.strictEqual(res5.statusCode, 200, 'Legitimate years should be allowed');
    console.log('✅ Secondary defense validation boundary checks verified.');
  } catch (error) {
    console.error('❌ Test Case 3 Failed:', error);
    throw error;
  }

  console.log('\n🔍 Test Case 4: Interception and zero-leakage check of Cloud AI prompts...');
  try {
    const sensitiveName = 'Tanya Jha';
    const sensitiveID = 'EMP12345';
    
    // Create candidate text
    const text = `Employee Name: ${sensitiveName}\nEmployee ID: ${sensitiveID}`;
    const localResult = await localProcessor.processDocumentText(text);

    // Assert that the labels sent to the cloud contain no sensitive values
    const labelsSent = localResult.safeLabels;
    assert.deepStrictEqual(labelsSent, ['Employee Name', 'Employee ID']);

    // Mock AI chat calls and assert that prompt/payload does not contain the sensitive values
    const originalChat = aiService.chat;
    let interceptedPrompt = '';
    
    aiService.chat = async (system: string, user: string) => {
      interceptedPrompt = `${system}\n${user}`;
      return JSON.stringify({
        'Employee Name': 'full_name',
        'Employee ID': 'employee_id'
      });
    };

    // Simulate backend call
    const req = { body: { labels: labelsSent } };
    const res = createMockResponse();
    await formAnalyzerController.mapStructure(req, res);
    
    // Restore original chat
    aiService.chat = originalChat;

    assert.strictEqual(res.statusCode, 200);
    
    // Verify zero PII leakage into AI payloads
    assert.ok(!interceptedPrompt.includes(sensitiveName), 'AI prompt must not contain sensitive name value');
    assert.ok(!interceptedPrompt.includes(sensitiveID), 'AI prompt must not contain sensitive ID value');
    
    console.log('✅ Interceptor check verified (zero sensitive values leaked to AI prompt).');
  } catch (error) {
    console.error('❌ Test Case 4 Failed:', error);
    throw error;
  }

  console.log('\n🔍 Test Case 5: Graceful degradation for unstructured/malformed text...');
  try {
    const rawText = 'This is a random sentence. It contains no key-value separators.';
    const result = await localProcessor.processDocumentText(rawText);
    assert.strictEqual(result.safeLabels.length, 0, 'Malformed lines should produce 0 safe labels');
    assert.strictEqual(result.allSegments[0].safeForCloud, false);
    assert.strictEqual(result.allSegments[0].value, rawText, 'Entire line kept local');
    console.log('✅ Graceful degradation verified.');
  } catch (error) {
    console.error('❌ Test Case 5 Failed:', error);
    throw error;
  }

  console.log('\n🔍 Test Case 6: Plaintext V1 OCR/extraction pipeline coexistence...');
  try {
    const ocrService = require('./services/ocrService');
    const text = 'Name: John Doe\nPAN: ABCDE1234F';
    const parsed = ocrService.parseStructuredData(text);
    
    assert.strictEqual(parsed.fullName, 'John Doe', 'V1 parseStructuredData must extract name');
    assert.strictEqual(parsed.panNumber, 'ABCDE1234F', 'V1 parseStructuredData must extract PAN');
    console.log('✅ Plaintext V1 OCR/extraction pipeline coexistence verified.');
  } catch (error) {
    console.error('❌ Test Case 6 Failed:', error);
    throw error;
  }

  console.log('\n🎉 All Secure Document Processing Pipeline tests passed successfully!');
}

runTests()
  .then(() => process.exit(0))
  .catch(() => process.exit(1));
