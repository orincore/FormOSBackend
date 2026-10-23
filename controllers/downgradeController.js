// Moving an account off Security V2.
//
// Security V2 is retired: documents are now read by the AI when they are uploaded, which an encrypted document cannot be. A V2
// member's documents can only be opened in their own browser with their PIN, so the browser does the work: it decrypts each
// document and sends a plain copy here (receiveCopy), the AI reads it like any upload, and only when every document has a copy
// that was read does finish() delete the encrypted originals and the vault keys and switch the account to standard.
// Nothing encrypted is deleted before its copy exists, and a run that stops half way can simply be started again.

const User = require('../models/User');
const Document = require('../models/Document');
const StorageService = require('../services/storageService');
const docFields = require('../services/documentFields');
const { savePlainDocument, PLAIN_UPLOAD_TYPES } = require('./documentController');

// The first bytes of the file must really be what its type says, so this cannot be used to store anything else.
const SIGNATURES = {
  'image/jpeg': (b) => b[0] === 0xff && b[1] === 0xd8,
  'image/png': (b) => b[0] === 0x89 && b.slice(1, 4).toString('latin1') === 'PNG',
  'application/pdf': (b) => b.slice(0, 4).toString('latin1') === '%PDF',
};

exports.receiveCopy = async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    if (user.securityVersion !== 2) return res.status(409).json({ success: false, code: 'ALREADY_STANDARD', message: 'This account already uses standard storage.' });
    if (!req.file) return res.status(400).json({ success: false, message: 'No file was sent.' });

    const source = await Document.findOne({ _id: req.body.sourceId, userId: req.userId, securityVersion: 2 });
    if (!source) return res.status(404).json({ success: false, message: 'The encrypted document was not found.' });

    // Safe to repeat: a document that already has its copy returns that copy.
    const existing = await Document.findOne({ userId: req.userId, migratedFrom: source._id }).select('ocrStatus');
    if (existing) return res.json({ success: true, document: { id: existing._id, ocrStatus: existing.ocrStatus }, alreadyCopied: true });

    const mimeType = req.file.mimetype;
    const check = SIGNATURES[mimeType];
    if (!PLAIN_UPLOAD_TYPES.includes(mimeType) || !check || !check(req.file.buffer)) {
      return res.status(415).json({ success: false, message: 'Only photos (JPG, PNG) and PDFs can be moved.' });
    }
    const name = String(req.body.originalName || req.file.originalname || 'document').replace(/[\\/\0]/g, '_').slice(0, 120);
    const document = await savePlainDocument({ userId: req.userId, buffer: req.file.buffer, originalName: name, mimeType, documentType: 'other', migratedFrom: source._id });
    return res.status(201).json({ success: true, document: { id: document._id, ocrStatus: document.ocrStatus } });
  } catch (error) {
    console.error('Move to standard storage (copy) error:', error.message);
    return res.status(500).json({ success: false, message: 'The copy could not be saved. Try again.' });
  }
};

// How far along the move is, so the app can show progress and wait for the AI to finish reading.
exports.status = async (req, res) => {
  try {
    const originals = await Document.find({ userId: req.userId, securityVersion: 2 }).select('_id');
    const copies = await Document.find({ userId: req.userId, migratedFrom: { $in: originals.map((d) => d._id) } }).select('migratedFrom ocrStatus');
    return res.json({
      success: true,
      originals: originals.length,
      copied: new Set(copies.map((c) => String(c.migratedFrom))).size,
      reading: copies.filter((c) => ['pending', 'processing'].includes(c.ocrStatus)).length,
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Could not check progress.' });
  }
};

exports.finish = async (req, res) => {
  try {
    if (req.body?.confirm !== true) return res.status(400).json({ success: false, message: 'Confirmation is required.' });
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    if (user.securityVersion !== 2) return res.status(409).json({ success: false, code: 'ALREADY_STANDARD', message: 'This account already uses standard storage.' });

    const originals = await Document.find({ userId: req.userId, securityVersion: 2 });
    const copies = await Document.find({ userId: req.userId, migratedFrom: { $in: originals.map((d) => d._id) } }).select('migratedFrom ocrStatus');
    const copied = new Set(copies.map((c) => String(c.migratedFrom)));
    const missing = originals.filter((o) => !copied.has(String(o._id))).length;
    const reading = copies.filter((c) => ['pending', 'processing'].includes(c.ocrStatus)).length;
    if (missing) return res.status(409).json({ success: false, code: 'COPIES_MISSING', message: `${missing} document${missing === 1 ? ' has' : 's have'} no standard copy yet, so nothing was deleted.` });
    if (reading) return res.status(409).json({ success: false, code: 'STILL_READING', message: 'The AI is still reading some of the copies. Wait a moment and try again.' });

    // Only now are the encrypted originals removed.
    let deleted = 0;
    for (const original of originals) {
      await StorageService.removeStored(original);
      await original.deleteOne();
      deleted += 1;
    }

    // The details used to fill forms are rebuilt from what the AI read, newest document first.
    const read = await Document.find({ userId: req.userId, securityVersion: { $ne: 2 }, ocrStatus: 'completed' }).sort({ uploadedAt: -1 }).select('structuredData');
    const profile = {};
    for (const key of docFields.KNOWN_KEYS) {
      for (const doc of read) {
        const value = docFields.cleanKnown(doc.structuredData || {})[key];
        if (value) { profile[key] = value; break; }
      }
    }
    await User.updateOne({ _id: user._id }, {
      $set: { securityVersion: 1, migrationStatus: 'pending', extractedData: { ...(user.extractedData || {}), ...profile } },
      $unset: { encryptedProfile: 1, userSalt: 1, wrappedUserKey: 1, wrappedUserKeyRecovery: 1 },
    });
    return res.json({ success: true, deleted, copies: copies.length });
  } catch (error) {
    console.error('Move to standard storage (finish) error:', error.message);
    return res.status(500).json({ success: false, message: 'The move could not be finished. Nothing more was deleted; you can run it again.' });
  }
};
