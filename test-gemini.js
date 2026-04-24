#!/usr/bin/env node
/**
 * Gemini API Test Script
 * Run this to verify your Gemini API key is working
 * Usage: node test-gemini.js
 */

require('dotenv').config();
const { GoogleGenerativeAI } = require('@google/generative-ai');

async function testGemini() {
  console.log('🔍 Testing Gemini API...\n');

  // Check if API key is set
  if (!process.env.GEMINI_API_KEY) {
    console.log('❌ GEMINI_API_KEY not found in .env file');
    console.log('   Add GEMINI_API_KEY to your .env file\n');
    return false;
  }

  if (process.env.GEMINI_API_KEY === 'your_gemini_api_key_here') {
    console.log('❌ GEMINI_API_KEY is still the placeholder value');
    console.log('   Get your API key from: https://makersuite.google.com/app/apikey\n');
    return false;
  }

  console.log('✅ API key found in .env');
  console.log(`   Key: ${process.env.GEMINI_API_KEY.substring(0, 10)}...\n`);

  // Test API connection
  try {
    console.log('🔍 Testing API connection...');
    const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
    
    // Try gemini-pro first (most stable)
    try {
      const model = genAI.getGenerativeModel({ model: 'gemini-pro' });
      const result = await model.generateContent('Say hello in one word');
      const response = await result.response;
      const text = response.text();
      
      console.log('✅ Successfully connected to Gemini API!');
      console.log(`   Model: gemini-pro`);
      console.log(`   Response: "${text}"\n`);
      
      return true;
    } catch (err) {
      console.log('⚠️  gemini-pro failed, trying gemini-1.5-flash...');
      
      const model2 = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });
      const result2 = await model2.generateContent('Say hello in one word');
      const response2 = await result2.response;
      const text2 = response2.text();
      
      console.log('✅ Successfully connected to Gemini API!');
      console.log(`   Model: gemini-1.5-flash`);
      console.log(`   Response: "${text2}"\n`);
      console.log('   Update aiService.js to use "gemini-1.5-flash"\n');
      
      return true;
    }
  } catch (error) {
    console.log('❌ Failed to connect to Gemini API');
    console.log(`   Error: ${error.message}\n`);
    
    if (error.message.includes('API_KEY_INVALID')) {
      console.log('   Your API key is invalid. Generate a new one at:');
      console.log('   https://makersuite.google.com/app/apikey\n');
    } else if (error.message.includes('404') || error.message.includes('not found')) {
      console.log('   Your API key might not have access to Gemini models yet.');
      console.log('   Try generating a new API key at:');
      console.log('   https://makersuite.google.com/app/apikey\n');
    }
    
    return false;
  }
}

// Run the test
testGemini()
  .then(success => {
    if (success) {
      console.log('🎉 Gemini API is working correctly!');
      console.log('   Your FormOS AI chat should work now.\n');
    } else {
      console.log('⚠️  Please fix the issues above and try again.\n');
    }
    process.exit(success ? 0 : 1);
  })
  .catch(error => {
    console.error('❌ Unexpected error:', error);
    process.exit(1);
  });
