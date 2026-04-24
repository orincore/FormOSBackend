#!/usr/bin/env node
/**
 * S3 Connection Test Script
 * Run this to verify your S3 configuration is working
 * Usage: node test-s3.js
 */

require('dotenv').config();
const { S3Client, HeadBucketCommand, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');

const s3Client = new S3Client({
  region: process.env.AWS_REGION || 'us-east-1',
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
  }
});

async function testS3Connection() {
  console.log('🔍 Testing S3 Configuration...\n');

  // Check if credentials are set
  if (!process.env.AWS_ACCESS_KEY_ID || !process.env.AWS_SECRET_ACCESS_KEY) {
    console.log('❌ AWS credentials not found in .env file');
    console.log('   Add AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY to your .env file\n');
    return false;
  }

  if (!process.env.AWS_S3_BUCKET) {
    console.log('❌ AWS_S3_BUCKET not found in .env file');
    console.log('   Add AWS_S3_BUCKET to your .env file\n');
    return false;
  }

  console.log('✅ Credentials found in .env');
  console.log(`   Region: ${process.env.AWS_REGION || 'us-east-1'}`);
  console.log(`   Bucket: ${process.env.AWS_S3_BUCKET}\n`);

  // Test bucket access
  try {
    console.log('🔍 Testing bucket access...');
    const command = new HeadBucketCommand({ Bucket: process.env.AWS_S3_BUCKET });
    await s3Client.send(command);
    console.log('✅ Successfully connected to S3 bucket!\n');
  } catch (error) {
    console.log('❌ Failed to access S3 bucket');
    console.log(`   Error: ${error.message}\n`);
    
    if (error.name === 'NotFound') {
      console.log('   The bucket does not exist or you don\'t have access to it');
    } else if (error.name === 'Forbidden') {
      console.log('   Access denied. Check your IAM permissions');
    }
    return false;
  }

  // Test write permissions
  try {
    console.log('🔍 Testing write permissions...');
    const testKey = 'test/connection-test.txt';
    const testContent = 'FormOS S3 connection test - ' + new Date().toISOString();
    
    const putCommand = new PutObjectCommand({
      Bucket: process.env.AWS_S3_BUCKET,
      Key: testKey,
      Body: testContent,
      ContentType: 'text/plain'
    });
    
    await s3Client.send(putCommand);
    console.log('✅ Successfully wrote test file to S3\n');

    // Test read permissions
    console.log('🔍 Testing read permissions...');
    const getCommand = new GetObjectCommand({
      Bucket: process.env.AWS_S3_BUCKET,
      Key: testKey
    });
    
    await s3Client.send(getCommand);
    console.log('✅ Successfully read test file from S3\n');

    // Test delete permissions
    console.log('🔍 Testing delete permissions...');
    const deleteCommand = new DeleteObjectCommand({
      Bucket: process.env.AWS_S3_BUCKET,
      Key: testKey
    });
    
    await s3Client.send(deleteCommand);
    console.log('✅ Successfully deleted test file from S3\n');

  } catch (error) {
    console.log('❌ Permission test failed');
    console.log(`   Error: ${error.message}\n`);
    
    if (error.name === 'AccessDenied') {
      console.log('   Your IAM user needs PutObject, GetObject, and DeleteObject permissions');
    }
    return false;
  }

  console.log('🎉 All S3 tests passed! Your configuration is working correctly.\n');
  console.log('📁 Files will be stored in S3 at: s3://' + process.env.AWS_S3_BUCKET + '/documents/[userId]/\n');
  return true;
}

// Run the test
testS3Connection()
  .then(success => {
    process.exit(success ? 0 : 1);
  })
  .catch(error => {
    console.error('❌ Unexpected error:', error);
    process.exit(1);
  });
