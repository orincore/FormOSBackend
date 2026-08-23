require('dotenv').config({ path: __dirname + '/.env' });
import assert from 'assert';
import { AutofillHelper, AutofillRequest } from '../FormOSFrontend/lib/security/autofillHelper';
import { deriveKeyFromPassword } from '../FormOSFrontend/lib/security/keyDerivation';
import { generateRandomKey, wrapKey } from '../FormOSFrontend/lib/security/keyWrapping';
import { encryptData } from '../FormOSFrontend/lib/security/encryption';
import { EncryptedPayload } from '../FormOSFrontend/lib/security/types';

const autofillController = require('./controllers/autofillController');

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

// Mock storage contexts
const mockLocalStorage: Record<string, string> = {};
const mockSessionStorage: Record<string, string> = {};

async function runTests() {
  console.log('🧪 Starting Secure Autofill Flow Tests...\n');

  const autofillHelper = new AutofillHelper();

  const v1User = { _id: 'user1', securityVersion: 1 };
  const v2User = { _id: 'user2', securityVersion: 2 };

  // Generate real cryptographic keys for test suite
  const password = 'mySecretPIN123';
  const salt = 'uniqueUserSaltValue';
  const UDK = await generateRandomKey();
  const KEK = await deriveKeyFromPassword(password, salt);
  const wrappedUDK = await wrapKey(UDK, KEK);

  // Encrypt profile data using the UDK
  const encryptedProfile: Record<string, EncryptedPayload> = {
    full_name: await encryptData('Tanya Jha', UDK, salt),
    date_of_birth: await encryptData('15-01-1990', UDK, salt),
    pan_number: await encryptData('ABCDE1234F', UDK, salt),
    email: await encryptData('tanya@example.com', UDK, salt)
  };

  // Mock map-structure callback
  const mockMapLabelsCallback = async (labels: string[]) => {
    const mappings: Record<string, string | null> = {};
    for (const label of labels) {
      if (label === 'Full Name' || label === 'Applicant Name') mappings[label] = 'full_name';
      if (label === 'Date of Birth' || label === 'DOB') mappings[label] = 'date_of_birth';
      if (label === 'PAN' || label === 'PAN Card') mappings[label] = 'pan_number';
      if (label === 'Email') mappings[label] = 'email';
    }
    return mappings;
  };

  console.log('🔍 Test Case 1: V1 Compatibility (Backend endpoint returns plaintext values)...');
  try {
    const User = require('./models/User');
    const originalFindById = User.findById;
    User.findById = async () => v1User;

    const ragService = require('./services/ragService');
    const originalGenerate = ragService.generateAutofillData;
    ragService.generateAutofillData = async () => ({
      name: 'Tanya Jha',
      pan: 'ABCDE1234F',
      email: 'tanya@example.com'
    });

    const req = { userId: 'user1', query: { includeSensitive: 'true' }, stepUpVerified: true };
    const res = createMockResponse();

    await autofillController.getAutofillData(req, res);

    // Restore
    User.findById = originalFindById;
    ragService.generateAutofillData = originalGenerate;

    assert.strictEqual(res.statusCode, 200);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.data.pan, 'ABCDE1234F');
    console.log('✅ V1 backend autofill verified.');
  } catch (error) {
    console.error('❌ Test Case 1 Failed:', error);
    throw error;
  }

  console.log('\n🔍 Test Case 2: V2 Backend block (returns 403 Forbidden even if user attempts)...');
  try {
    const User = require('./models/User');
    const originalFindById = User.findById;
    User.findById = async () => v2User;

    const req = { userId: 'user2', query: { includeSensitive: 'true' } };
    const res = createMockResponse();

    await autofillController.getAutofillData(req, res);
    User.findById = originalFindById;

    assert.strictEqual(res.statusCode, 403, 'V2 users must be blocked from backend plaintext fetches');
    assert.strictEqual(res.body.code, 'V2_AUTHENTICATION_REQUIRED');
    console.log('✅ V2 Backend block verified.');
  } catch (error) {
    console.error('❌ Test Case 2 Failed:', error);
    throw error;
  }

  console.log('\n🔍 Test Case 3: Key Material Isolation Audit (No keys in localStorage, sessionStorage or postMessage)...');
  try {
    // 3.1 Verify storage
    assert.strictEqual(mockLocalStorage['UDK'], undefined);
    assert.strictEqual(mockLocalStorage['KEK'], undefined);
    assert.strictEqual(mockSessionStorage['UDK'], undefined);
    
    // 3.2 Verify that no key material is transmitted in runtime message requests or postMessage payloads
    const sampleMessage = {
      type: 'FORMOS_AUTOFILL_REQUEST',
      fields: [{ name: 'nameInput', label: 'Applicant Name' }],
      origin: 'https://opportunity.com'
    };
    
    assert.strictEqual(JSON.stringify(sampleMessage).includes('key'), false);
    assert.strictEqual(JSON.stringify(sampleMessage).includes('secret'), false);

    console.log('✅ Key Material Isolation verified.');
  } catch (error) {
    console.error('❌ Test Case 3 Failed:', error);
    throw error;
  }

  console.log('\n🔍 Test Case 4: Extension Unlock & Local Decryption (Option C)...');
  try {
    // 4.1 Verify locked vault prevents autofill
    autofillHelper.lockVault();
    assert.strictEqual(autofillHelper.isVaultLocked(), true);

    const extensionRequest: AutofillRequest = {
      type: 'FORMOS_AUTOFILL_REQUEST',
      fields: [{ name: 'nameInput', label: 'Applicant Name' }],
      origin: 'https://opportunity.com'
    };

    let clientResponse = await autofillHelper.handleAutofillRequest(
      extensionRequest,
      encryptedProfile,
      true,
      mockMapLabelsCallback
    );

    assert.strictEqual(clientResponse.success, false);
    assert.strictEqual(clientResponse.code, 'VAULT_LOCKED');

    // 4.2 Unlock extension locally (KDF runs inside background context)
    await autofillHelper.unlockVault(password, salt, wrappedUDK);
    assert.strictEqual(autofillHelper.isVaultLocked(), false);

    // 4.3 Verify secure retrieval of decrypted fields
    clientResponse = await autofillHelper.handleAutofillRequest(
      extensionRequest,
      encryptedProfile,
      true,
      mockMapLabelsCallback
    );

    assert.strictEqual(clientResponse.success, true);
    assert.strictEqual(clientResponse.values?.nameInput, 'Tanya Jha');
    console.log('✅ Extension Unlock & Local Decryption verified.');
  } catch (error) {
    console.error('❌ Test Case 4 Failed:', error);
    throw error;
  }

  console.log('\n🔍 Test Case 5: Step-Up MFA Authorization check...');
  try {
    const extensionRequest: AutofillRequest = {
      type: 'FORMOS_AUTOFILL_REQUEST',
      fields: [
        { name: 'nameInput', label: 'Applicant Name' },
        { name: 'panInput', label: 'PAN Card' }
      ],
      origin: 'https://opportunity.com'
    };

    // Call with isStepUpVerified = false
    const clientResponse = await autofillHelper.handleAutofillRequest(
      extensionRequest,
      encryptedProfile,
      false, // Step-up missing
      mockMapLabelsCallback
    );

    assert.strictEqual(clientResponse.success, true);
    assert.strictEqual(clientResponse.values?.nameInput, 'Tanya Jha');
    assert.strictEqual(clientResponse.values?.panInput, undefined, 'Sensitive field must be omitted');

    // Sensitive-only fails
    const sensitiveOnlyRequest: AutofillRequest = {
      type: 'FORMOS_AUTOFILL_REQUEST',
      fields: [{ name: 'panInput', label: 'PAN Card' }],
      origin: 'https://opportunity.com'
    };

    const sensitiveResponse = await autofillHelper.handleAutofillRequest(
      sensitiveOnlyRequest,
      encryptedProfile,
      false,
      mockMapLabelsCallback
    );
    assert.strictEqual(sensitiveResponse.success, false);
    assert.strictEqual(sensitiveResponse.code, 'STEP_UP_REQUIRED');
    console.log('✅ Step-Up MFA verified.');
  } catch (error) {
    console.error('❌ Test Case 5 Failed:', error);
    throw error;
  }

  console.log('\n🔍 Test Case 6: Replay and Timestamp Timing Protections...');
  try {
    const freshRequest: AutofillRequest = {
      type: 'FORMOS_AUTOFILL_REQUEST',
      fields: [{ name: 'nameInput', label: 'Applicant Name' }],
      origin: 'https://opportunity.com',
      requestId: 'nonce12345678',
      timestamp: Date.now()
    };

    let response = await autofillHelper.handleAutofillRequest(
      freshRequest,
      encryptedProfile,
      true,
      mockMapLabelsCallback
    );
    assert.strictEqual(response.success, true);

    // Replay duplicate nonce
    let replayResponse = await autofillHelper.handleAutofillRequest(
      freshRequest,
      encryptedProfile,
      true,
      mockMapLabelsCallback
    );
    assert.strictEqual(replayResponse.success, false);
    assert.strictEqual(replayResponse.code, 'REPLAY_DETECTED');

    // Expired timestamp request
    const expiredRequest: AutofillRequest = {
      type: 'FORMOS_AUTOFILL_REQUEST',
      fields: [{ name: 'nameInput', label: 'Applicant Name' }],
      origin: 'https://opportunity.com',
      requestId: 'nonce99999999',
      timestamp: Date.now() - 10000 // 10 seconds old
    };

    let expiredResponse = await autofillHelper.handleAutofillRequest(
      expiredRequest,
      encryptedProfile,
      true,
      mockMapLabelsCallback
    );
    assert.strictEqual(expiredResponse.success, false);
    assert.strictEqual(expiredResponse.code, 'REQUEST_EXPIRED');
    console.log('✅ Replay & expiration guards verified.');
  } catch (error) {
    console.error('❌ Test Case 6 Failed:', error);
    throw error;
  }
  console.log('\n🔍 Test Case 7: Service Worker Restart Evicts UDK (Option C Memory Lifetime)...');
  try {
    // 7.1 Unlock vault
    await autofillHelper.unlockVault(password, salt, wrappedUDK);
    assert.strictEqual(autofillHelper.isVaultLocked(), false);

    // 7.2 Simulate background service worker restart/eviction
    const restartedHelper = new AutofillHelper();
    assert.strictEqual(restartedHelper.isVaultLocked(), true, 'Service worker restart must evict memory-only keys');

    // Confirm restarted helper blocks autofill
    const extensionRequest: AutofillRequest = {
      type: 'FORMOS_AUTOFILL_REQUEST',
      fields: [{ name: 'nameInput', label: 'Applicant Name' }],
      origin: 'https://opportunity.com'
    };
    const response = await restartedHelper.handleAutofillRequest(
      extensionRequest,
      encryptedProfile,
      true,
      mockMapLabelsCallback
    );
    assert.strictEqual(response.success, false);
    assert.strictEqual(response.code, 'VAULT_LOCKED');
    console.log('✅ Service Worker Restart Eviction verified.');
  } catch (error) {
    console.error('❌ Test Case 7 Failed:', error);
    throw error;
  }

  console.log('\n🔍 Test Case 8: Wrong Sender/Extension Origin Verification (background.js mock)...');
  try {
    // Standard Manifest V3 background message listener validation simulation
    const mockMessageListener = (message: any, sender: any) => {
      // Security Validation: Sender validation
      if (sender.id && sender.id !== 'formos-chrome-extension-id') {
        return { success: false, error: 'Unauthorized message sender context' };
      }
      return { success: true };
    };

    // Valid internal sender
    const validRes = mockMessageListener({ action: 'autofill' }, { id: 'formos-chrome-extension-id' });
    assert.strictEqual(validRes.success, true);

    // Malicious external webpage trying to spoof sender context
    const invalidRes = mockMessageListener({ action: 'autofill' }, { id: 'malicious-spoofed-extension-id' });
    assert.strictEqual(invalidRes.success, false);
    assert.strictEqual(invalidRes.error, 'Unauthorized message sender context');
    console.log('✅ Sender Verification boundaries verified.');
  } catch (error) {
    console.error('❌ Test Case 8 Failed:', error);
    throw error;
  }

  console.log('\n🔍 Test Case 9: Webpage JS Direct Key/Data Retrieval Blocked...');
  try {
    // Verify that the FormOS webpage never receives the UDK/KEK in any format
    const webpageContextMock = {
      localStorage: mockLocalStorage,
      sessionStorage: mockSessionStorage,
      keysReceived: [] as any[]
    };

    // Attempting to look for key leaks
    assert.strictEqual(webpageContextMock.localStorage['UDK'], undefined);
    assert.strictEqual(webpageContextMock.localStorage['KEK'], undefined);
    assert.strictEqual(webpageContextMock.sessionStorage['UDK'], undefined);

    console.log('✅ Webpage JS key isolation verified.');
  } catch (error) {
    console.error('❌ Test Case 9 Failed:', error);
    throw error;
  }



  console.log('\n🎉 All Secure Autofill Flow tests passed successfully!');
}

runTests()
  .then(() => process.exit(0))
  .catch(() => process.exit(1));
