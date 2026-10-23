const myData = require('../services/myData');

// GET /api/mydata (masked) and GET /api/mydata/reveal (full values, after a recent PIN check)
exports.get = (reveal) => async (req, res) => {
  try {
    const data = await myData.collect(req.userId, { reveal });
    if (!data) return res.status(404).json({ success: false, message: 'Account not found.' });
    return res.json({ success: true, revealed: reveal, ...data });
  } catch (error) {
    console.error('My data error:', error.message);
    return res.status(500).json({ success: false, message: 'Your data could not be loaded.' });
  }
};

const answer = (res, result, okBody = {}) => (result.error
  ? res.status(400).json({ success: false, message: result.error })
  : res.json({ success: true, ...okBody }));

const guard = (fn) => async (req, res) => {
  try { return await fn(req, res); } catch (error) {
    console.error('My data change error:', error.message);
    return res.status(500).json({ success: false, message: 'That could not be saved. Try again.' });
  }
};

exports.setProfile = guard(async (req, res) => {
  const result = await myData.setProfileField(req.userId, req.params.key, req.body?.value);
  return answer(res, result, { documents: result.documents, message: result.documents ? `Saved on your profile and ${result.documents} document${result.documents === 1 ? '' : 's'}.` : 'Saved.' });
});

exports.deleteProfile = guard(async (req, res) => {
  const result = await myData.deleteProfileField(req.userId, req.params.key, { everywhere: String(req.query.everywhere) !== 'false' });
  return answer(res, result, { documents: result.documents });
});

exports.setDocumentField = guard(async (req, res) => answer(res, await myData.setDocumentField(req.userId, req.params.id, req.params.key, req.body?.value), { message: 'Saved.' }));
exports.deleteDocumentField = guard(async (req, res) => answer(res, await myData.deleteDocumentField(req.userId, req.params.id, req.params.key)));
exports.clearDocument = guard(async (req, res) => answer(res, await myData.clearDocumentData(req.userId, req.params.id)));
exports.deleteCustom = guard(async (req, res) => answer(res, await myData.deleteCustomField(req.userId, req.params.label)));

// POST /api/mydata/forget { scope: 'details' | 'everything', confirm: 'DELETE' }
exports.forget = guard(async (req, res) => {
  const scope = req.body?.scope;
  if (!['details', 'everything'].includes(scope)) return res.status(400).json({ success: false, message: 'Choose what to remove.' });
  if (req.body?.confirm !== 'DELETE') return res.status(400).json({ success: false, message: 'Type DELETE to confirm.' });
  const result = await myData.forget(req.userId, { documents: scope === 'everything' });
  return res.json({ success: true, ...result });
});
