const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, HeadBucketCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const multerS3 = require('multer-s3');
const path = require('path');

// Object storage for uploaded files. Cloudflare R2 is used when its settings are present, otherwise AWS S3.
// R2 speaks the S3 protocol, so the rest of the app keeps calling the same functions.
//
//   R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET   (R2_ENDPOINT overrides the address)
//   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_S3_BUCKET, AWS_REGION
const isR2Configured = () => !!(
  (process.env.R2_ENDPOINT || process.env.R2_ACCOUNT_ID) &&
  process.env.R2_ACCESS_KEY_ID &&
  process.env.R2_SECRET_ACCESS_KEY &&
  process.env.R2_BUCKET
);

const isAwsConfigured = () => !!(
  process.env.AWS_ACCESS_KEY_ID &&
  process.env.AWS_SECRET_ACCESS_KEY &&
  process.env.AWS_S3_BUCKET
);

// Kept under its old name because callers only ask "is there object storage".
const isS3Configured = () => isR2Configured() || isAwsConfigured();
const storageProvider = () => (isR2Configured() ? 'r2' : isAwsConfigured() ? 'aws' : 'none');
const bucketName = () => (isR2Configured() ? process.env.R2_BUCKET : process.env.AWS_S3_BUCKET);

const buildClient = () => {
  if (isR2Configured()) {
    return new S3Client({
      region: 'auto',
      endpoint: process.env.R2_ENDPOINT || `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
      forcePathStyle: true,
      credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY },
      // R2 does not accept the extra checksum headers newer SDK versions add by default.
      requestChecksumCalculation: 'WHEN_REQUIRED',
      responseChecksumValidation: 'WHEN_REQUIRED',
    });
  }
  if (isAwsConfigured()) {
    return new S3Client({
      region: process.env.AWS_REGION || 'us-east-1',
      credentials: { accessKeyId: process.env.AWS_ACCESS_KEY_ID, secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY },
    });
  }
  return null;
};

const s3Client = buildClient();

const s3Storage = s3Client
  ? multerS3({
      s3: s3Client,
      bucket: bucketName(),
      ...(isR2Configured() ? {} : { acl: 'private' }), // R2 has no ACLs: every object is private
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
    throw new Error('Object storage is not configured');
  }
};

const locationFor = (key) => (isR2Configured()
  ? `r2://${bucketName()}/${key}`
  : `https://${bucketName()}.s3.${process.env.AWS_REGION || 'us-east-1'}.amazonaws.com/${key}`);

// Store bytes under an exact key.
const putObject = async (key, body, contentType) => {
  assertS3Configured();
  try {
    await s3Client.send(new PutObjectCommand({
      Bucket: bucketName(),
      Key: key,
      Body: body,
      ContentType: contentType || 'application/octet-stream',
      ...(isR2Configured() ? {} : { ACL: 'private' }),
    }));
    return { location: locationFor(key), key, bucket: bucketName() };
  } catch (error) {
    console.error(`${storageProvider().toUpperCase()} upload error:`, error.message);
    throw new Error('Failed to upload file to storage');
  }
};

// Upload a user's file under documents/<userId>/<filename>
const uploadToS3 = (fileBuffer, filename, mimetype, userId) => putObject(`documents/${userId}/${filename}`, fileBuffer, mimetype);

// Get signed URL for temporary access
const getS3SignedUrl = async (key, expiresIn = 3600) => {
  assertS3Configured();
  return await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: bucketName(), Key: key }), { expiresIn });
};

// Download file from storage
const downloadFromS3 = async (key) => {
  assertS3Configured();
  try {
    const response = await s3Client.send(new GetObjectCommand({ Bucket: bucketName(), Key: key }));
    const chunks = [];
    for await (const chunk of response.Body) chunks.push(chunk);
    return Buffer.concat(chunks);
  } catch (error) {
    console.error(`${storageProvider().toUpperCase()} download error:`, error.message);
    throw new Error('Failed to download file from storage');
  }
};

// Delete file from storage
const deleteFromS3 = async (key) => {
  assertS3Configured();
  try {
    await s3Client.send(new DeleteObjectCommand({ Bucket: bucketName(), Key: key }));
    return true;
  } catch (error) {
    console.error(`${storageProvider().toUpperCase()} delete error:`, error.message);
    throw new Error('Failed to delete file from storage');
  }
};

// Proves the settings work end to end: reaches the bucket, then writes, reads back and deletes a test file.
const checkStorage = async () => {
  const provider = storageProvider();
  if (provider === 'none') return { ok: false, provider, step: 'configuration', message: 'No object storage settings found.' };
  const key = `healthcheck/${Date.now()}-${Math.round(Math.random() * 1e9)}.txt`;
  const body = `formos storage check ${new Date().toISOString()}`;
  let step = 'reaching the bucket';
  try {
    await s3Client.send(new HeadBucketCommand({ Bucket: bucketName() }));
    step = 'writing a test file';
    await putObject(key, Buffer.from(body), 'text/plain');
    step = 'reading it back';
    const back = (await downloadFromS3(key)).toString('utf8');
    if (back !== body) throw new Error('The file read back did not match what was written.');
    step = 'deleting the test file';
    await deleteFromS3(key);
    return { ok: true, provider, bucket: bucketName() };
  } catch (error) {
    return { ok: false, provider, bucket: bucketName(), step, message: error.message };
  }
};

module.exports = {
  s3Client,
  s3Storage,
  isS3Configured,
  isR2Configured,
  storageProvider,
  putObject,
  uploadToS3,
  getS3SignedUrl,
  downloadFromS3,
  deleteFromS3,
  checkStorage
};
