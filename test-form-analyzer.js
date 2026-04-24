/**
 * Test script for Enhanced Form Analyzer feature
 * Run with: node test-form-analyzer.js
 */

const formAnalyzerService = require('./services/formAnalyzerService');

// Mock user data
const mockUserData = {
  fullName: 'John Doe',
  dateOfBirth: '15/01/1990',
  address: '123 Main Street, New York, NY 10001',
  phone: '+1234567890',
  email: 'john.doe@example.com',
  aadhaarNumber: '123456789012',
  panNumber: 'ABCDE1234F'
};

console.log('=== Enhanced Form Analyzer Tests ===\n');

// Test Case 1: Mock form fields with various match types
console.log('=== Test Case 1: Various Match Types ===\n');

const mockFormFields = [
  'Full Name',        // Exact match
  'DOB',             // Synonym match
  'Email',           // Exact match
  'Mobile',          // Synonym match
  'Street',          // Partial match
  'Company Name',    // No match
  'Surname'          // Partial match
];

const result1 = formAnalyzerService.analyzeMockForm(mockFormFields, mockUserData);

console.log('Form Fields:', mockFormFields);
console.log('\n📊 Analysis Summary:');
console.log('- Total Fields:', result1.totalFields);
console.log('- Match Percentage:', result1.matchPercentage + '%');
console.log('- Average Confidence:', (parseFloat(result1.analysis.averageConfidence) * 100).toFixed(0) + '%');
console.log('- Completion Status:', result1.analysis.completionStatus);

console.log('\n🎯 Confidence Breakdown:');
console.log('- High Confidence:', result1.confidenceBreakdown.high);
console.log('- Medium Confidence:', result1.confidenceBreakdown.medium);
console.log('- Low Confidence:', result1.confidenceBreakdown.low);
console.log('- No Match:', result1.confidenceBreakdown.none);

console.log('\n📋 Field Details:');
result1.matchDetails.forEach(field => {
  const icon = field.confidence >= 0.8 ? '✅' :
               field.confidence >= 0.6 ? '⚠️' :
               field.confidence > 0 ? '⚡' : '❌';
  const confidencePercent = (field.confidence * 100).toFixed(0);
  console.log(`${icon} ${field.fieldName}`);
  console.log(`   Confidence: ${confidencePercent}% | Reason: ${field.reason}`);
  if (field.mappedTo) {
    console.log(`   Mapped to: ${field.mappedTo} | Value: ${field.value}`);
  }
  console.log(`   Suggestion: ${field.suggestion.message}`);
  console.log('');
});

console.log('💡 Insights:');
result1.insights.forEach(insight => {
  console.log(`${insight.icon} ${insight.title}: ${insight.message}`);
});

console.log('\n⚡ Autofill Data:');
console.log('- Can Autofill:', result1.autofillData.canAutofill);
console.log('- Field Count:', result1.autofillData.fieldCount);
if (result1.autofillData.canAutofill) {
  console.log('- Autofillable Fields:', result1.autofillData.fields.map(f => f.fieldName).join(', '));
}

console.log('\n🤖 AI Context:');
const aiContext = formAnalyzerService.generateAIContext(result1);
console.log('Summary:', aiContext.summary);
console.log('Completion Rate:', aiContext.completionRate);
console.log('\nNext Steps:');
aiContext.nextSteps.forEach((step, idx) => {
  console.log(`${idx + 1}. ${step.action}`);
  console.log(`   ${step.description}`);
});

// Test Case 2: Government form
console.log('\n\n=== Test Case 2: Government Form ===\n');

const govFormFields = [
  'Full Name',
  'Date of Birth',
  'Aadhaar Number',
  'PAN Number',
  'Address',
  'Nationality'
];

const result2 = formAnalyzerService.analyzeMockForm(govFormFields, mockUserData);

console.log('Form Fields:', govFormFields);
console.log('\n📊 Analysis Summary:');
console.log('- Match Percentage:', result2.matchPercentage + '%');
console.log('- Ready to Autofill:', result2.analysis.readyToAutofill);
console.log('- Needs Verification:', result2.analysis.needsVerification);
console.log('- Missing Data:', result2.analysis.needsInput);

console.log('\n📋 Quick Field Status:');
result2.matchDetails.forEach(field => {
  const status = field.canAutofill ? '✅ Ready' :
                 field.confidence > 0 ? '⚠️ Verify' : '❌ Missing';
  console.log(`${status} - ${field.fieldName} (${(field.confidence * 100).toFixed(0)}%)`);
});

// Test Case 3: Empty user data
console.log('\n\n=== Test Case 3: Empty User Data ===\n');

const emptyUserData = {};
const result3 = formAnalyzerService.analyzeMockForm(mockFormFields, emptyUserData);

console.log('Form Fields:', mockFormFields);
console.log('\n📊 Analysis Summary:');
console.log('- Match Percentage:', result3.matchPercentage + '%');
console.log('- All fields missing:', result3.missingFields.length);

console.log('\n💡 Primary Insight:');
if (result3.insights.length > 0) {
  const mainInsight = result3.insights[0];
  console.log(`${mainInsight.icon} ${mainInsight.title}`);
  console.log(`   ${mainInsight.message}`);
}

console.log('\n✅ All enhanced tests completed!');
console.log('\n🎯 New Features Demonstrated:');
console.log('✓ Match explanations (exact, synonym, partial, fuzzy)');
console.log('✓ Confidence scoring (0-100%)');
console.log('✓ Suggested actions for each field');
console.log('✓ Autofill integration data');
console.log('✓ AI context generation');
console.log('✓ Actionable insights');
console.log('✓ Confidence breakdown');

