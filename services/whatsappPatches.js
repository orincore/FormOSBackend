// Fixes for whatsapp-web.js 1.34.7 against the current WhatsApp Web, applied at runtime so a reinstall cannot undo them
// (the fixed version is not released yet; upstream wwebjs/whatsapp-web.js issues 201830, 201833 and PR 201832).
//
// 1. WhatsApp renamed a message id's `_serialized` to `$1`. The library reads `_serialized`, gets undefined and looks up
//    "undefined" in WhatsApp's database, which fails with the unreadable `r: r`.
// 2. The library never tells WhatsApp the file's mimetype when it downloads media, so WhatsApp refuses photos
//    (documents slip through). The declared mimetype is passed now.
// Errors from inside the page are also turned into readable text instead of a minified `r: r`.
const { Message, MessageMedia } = require('whatsapp-web.js');

// The id as "fromMe_remote_id", whichever shape WhatsApp used.
function serializedId(id) {
  if (!id) return undefined;
  if (typeof id === 'string') return id;
  return id._serialized || id.$1 || (id.remote && id.id ? `${id.fromMe}_${id.remote}_${id.id}` : undefined);
}

// Puts `_serialized` back on a message's id so every other library call that reads it keeps working.
function normalizeMessageId(msg) {
  const id = msg?.id;
  if (id && typeof id === 'object' && !id._serialized) {
    const value = serializedId(id);
    if (value) id._serialized = value;
  }
  return msg;
}

let applied = false;
function applyWhatsAppPatches() {
  if (applied) return;
  applied = true;

  Message.prototype.downloadMedia = async function downloadMedia() {
    if (!this.hasMedia) return undefined;
    const msgId = serializedId(this.id);
    if (!msgId) throw new Error('The message has no usable id, so its file cannot be fetched.');

    const result = await this.client.pupPage.evaluate(async (id) => {
      try {
        const collections = window.require('WAWebCollections');
        const msg = collections.Msg.get(id) || (await collections.Msg.getMessagesById([id]))?.messages?.[0];

        // REUPLOADING means the file expired on WhatsApp's servers and cannot be downloaded right now.
        if (!msg || !msg.mediaData || msg.mediaData.mediaStage === 'REUPLOADING') return null;
        if (msg.mediaData.mediaStage !== 'RESOLVED') {
          await msg.downloadMedia({ downloadEvenIfExpensive: true, rmrReason: 1 });
        }
        if (msg.mediaData.mediaStage.includes('ERROR') || msg.mediaData.mediaStage === 'FETCHING') return undefined;

        const mockQpl = { addAnnotations() { return this; }, addPoint() { return this; } };
        let decrypted;
        try {
          decrypted = await window.require('WAWebDownloadManager').downloadManager.downloadAndMaybeDecrypt({
            directPath: msg.directPath,
            encFilehash: msg.encFilehash,
            filehash: msg.filehash,
            mediaKey: msg.mediaKey,
            mediaKeyTimestamp: msg.mediaKeyTimestamp,
            type: msg.type,
            mimetype: msg.mimetype,
            signal: new AbortController().signal,
            downloadQpl: mockQpl,
          });
        } catch (e) {
          if (e && e.status === 404) return undefined;
          throw e;
        }
        const data = await window.WWebJS.arrayBufferToBase64Async(decrypted);
        return { data, mimetype: msg.mimetype, filename: msg.filename, filesize: msg.size };
      } catch (e) {
        // WhatsApp's own errors are minified ("r: r"); say what failed and in which state instead.
        return { error: `${(e && (e.name || e.constructor?.name)) || 'Error'}: ${(e && e.message) || String(e)}`.slice(0, 200) };
      }
    }, msgId);

    if (!result) return undefined;
    if (result.error) throw new Error(`WhatsApp could not give the file (${result.error})`);
    return new MessageMedia(result.mimetype, result.data, result.filename, result.filesize);
  };
}

module.exports = { applyWhatsAppPatches, normalizeMessageId, serializedId };
