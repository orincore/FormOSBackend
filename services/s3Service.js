const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const multerS3 = require('multer-s3');
const path = require('path');

// Check if S3 is configured
const isS3Configured = () => {
  return !!(process.env.AWS_ACCESS_KEY_ID && 
            process.env.AWS_SECRET_ACCESS_KEY && 
            process.env.AWS_S3_BUCKET);
};

const s3Client = isS3Configured()
  ? new S3Client({
      region: process.env.AWS_REGION || 'us-east-1',
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
      }
    })
  : null;

const s3Storage = isS3Configured()
  ? multerS3({
      s3: s3Client,
      bucket: process.env.AWS_S3_BUCKET,
      acl: 'private',
      metadata: (req, file, cb) => {
        cb(null, {
          fieldName: file.fieldname,
          userId: req.userId?.toString() || 'unknown'
        });
      },
      key: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const filename = file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname);
        cb(null, `documents/${req.userId}/${filename}`);
      }
    })
  : null;

const assertS3Configured = () => {
  if (!isS3Configured() || !s3Client) {
    throw new Error('AWS S3 is not configured');
  }
};

// Upload file to S3
const uploadToS3 = async (fileBuffer, filename, mimetype, userId) => {
  assertS3Configured();
  const key = `documents/${userId}/${filename}`;
  const command = new PutObjectCommand({
    Bucket: process.env.AWS_S3_BUCKET,
    Key: key,
    Body: fileBuffer,
    ContentType: mimetype,
    ACL: 'private'
  });

  try {
    await s3Client.send(command);
    return {
      location: `https://${process.env.AWS_S3_BUCKET}.s3.${process.env.AWS_REGION || 'us-east-1'}.amazonaws.com/${key}`,
      key: key,
      bucket: process.env.AWS_S3_BUCKET
    };
  } catch (error) {
    console.error('S3 upload error:', error);
    throw new Error('Failed to upload file to S3');
  }
};

// Get signed URL for temporary access
const getS3SignedUrl = async (key, expiresIn = 3600) => {
  assertS3Configured();
  const command = new GetObjectCommand({
    Bucket: process.env.AWS_S3_BUCKET,
    Key: key
  });

  return await getSignedUrl(s3Client, command, { expiresIn });
};

// Download file from S3
const downloadFromS3 = async (key) => {
  assertS3Configured();
  const command = new GetObjectCommand({
    Bucket: process.env.AWS_S3_BUCKET,
    Key: key
  });

  try {
    const response = await s3Client.send(command);
    // Convert stream to buffer
    const chunks = [];
    for await (const chunk of response.Body) {
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  } catch (error) {
    console.error('S3 download error:', error);
    throw new Error('Failed to download file from S3');
  }
};

// Delete file from S3
const deleteFromS3 = async (key) => {
  assertS3Configured();
  const command = new DeleteObjectCommand({
    Bucket: process.env.AWS_S3_BUCKET,
    Key: key
  });

  try {
    await s3Client.send(command);
    return true;
  } catch (error) {
    console.error('S3 delete error:', error);
    throw new Error('Failed to delete file from S3');
  }
};

module.exports = {
  s3Client,
  s3Storage,
  isS3Configured,
  uploadToS3,
  getS3SignedUrl,
  downloadFromS3,
  deleteFromS3
};
