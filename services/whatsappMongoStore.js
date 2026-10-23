const fs = require('fs');
const path = require('path');

// Keeps the WhatsApp login in MongoDB (GridFS) so it survives restarts, redeploys and new servers. whatsapp-web.js's
// RemoteAuth zips the browser profile to <dataPath>/<session>.zip and asks the store to save or restore that file.
// (The wwebjs-mongo package reads the zip from the working directory instead, which is not where RemoteAuth puts it.)
const KEEP_VERSIONS = 2; // the newest backup plus one older one, in case the newest is damaged

class WhatsAppMongoStore {
  constructor({ mongoose, dataPath }) {
    if (!mongoose) throw new Error('A mongoose instance is required for the WhatsApp session store.');
    this.mongoose = mongoose;
    this.dataPath = dataPath;
    this.preferOlder = false;
  }

  bucket(session) {
    if (this.mongoose.connection.readyState !== 1) throw new Error('MongoDB is not connected, so the WhatsApp login cannot be loaded or saved.');
    return new this.mongoose.mongo.GridFSBucket(this.mongoose.connection.db, { bucketName: `whatsapp-${session}` });
  }

  zipPath(session) {
    return path.join(this.dataPath, `${session}.zip`);
  }

  async sessionExists({ session }) {
    return (await this.mongoose.connection.db.collection(`whatsapp-${session}.files`).countDocuments({ filename: `${session}.zip` })) > 0;
  }

  // Uploads the new backup first and only then removes old ones, so there is never a moment with no saved login.
  async save({ session }) {
    const bucket = this.bucket(session);
    const file = this.zipPath(session);
    await new Promise((resolve, reject) => {
      fs.createReadStream(file).on('error', reject)
        .pipe(bucket.openUploadStream(`${session}.zip`, { metadata: { savedAt: new Date() } }))
        .on('error', reject).on('finish', resolve);
    });
    const all = await bucket.find({ filename: `${session}.zip` }).sort({ uploadDate: -1 }).toArray();
    for (const old of all.slice(KEEP_VERSIONS)) await bucket.delete(old._id).catch(() => {});
  }

  async extract({ session, path: outPath }) {
    const bucket = this.bucket(session);
    const versions = await bucket.find({ filename: `${session}.zip` }).sort({ uploadDate: -1 }).limit(2).toArray();
    // After the newest backup has failed to load twice, the one before it is tried (see WhatsAppService.watchStuck).
    const latest = this.preferOlder && versions.length > 1 ? versions[1] : versions[0];
    if (!latest) throw new Error('No saved WhatsApp login found in MongoDB.');
    await new Promise((resolve, reject) => {
      bucket.openDownloadStream(latest._id).on('error', reject)
        .pipe(fs.createWriteStream(outPath)).on('error', reject).on('finish', resolve);
    });
  }

  async delete({ session }) {
    const bucket = this.bucket(session);
    for (const doc of await bucket.find({ filename: `${session}.zip` }).toArray()) await bucket.delete(doc._id);
  }
}

module.exports = WhatsAppMongoStore;
