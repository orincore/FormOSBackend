const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const QRCode = require('qrcode');

const CLIENT_ID = 'formos';
const STALE_START_MS = 150 * 1000;
const MIN_SEND_GAP_MS = 1200;
const RECONNECT_STEPS_MS = [5000, 15000, 45000, 120000, 300000];

// The one WhatsApp account FormOS sends from. It is linked once by scanning a QR code in the admin
// console. The login is kept on disk (WHATSAPP_SESSION_DIR), so a restart reconnects without a new scan.
class WhatsAppService {
  constructor() {
    this.client = null;
    this.state = 'stopped'; // stopped | starting | qr | authenticating | ready | failed | logged_out
    this.qrDataUrl = null;
    this.qrAt = null;
    this.info = null;
    this.error = null;
    this.since = Date.now();
    this.wanted = false;
    this.reconnectAttempt = 0;
    this.timers = new Set();
    this.sendChain = Promise.resolve();
    this.lastSendAt = 0;
    this.messageHandler = null;
    this.seen = new Set();
    this.lockHeld = false;
    // If this process dies, never leave its browser behind holding the saved login.
    process.on('exit', () => { this.releaseLock(); this.killBrowserNow(); });
    // Counts only, never message content: they show an admin whether the assistant is receiving and answering.
    this.stats = { received: 0, answered: 0, ignoredStranger: 0, ignoredOther: 0, unresolved: 0, failed: 0, lastReceivedAt: null, lastAnsweredAt: null, lastError: null };
  }

  isEnabled() {
    return process.env.WHATSAPP_ENABLED !== 'false';
  }

  sessionRoot() {
    return path.resolve(process.env.WHATSAPP_SESSION_DIR || path.join(__dirname, '..', '.wwebjs_auth'));
  }

  sessionDir() {
    return path.join(this.sessionRoot(), `session-${CLIENT_ID}`);
  }

  hasSavedSession() {
    try {
      return fs.existsSync(path.join(this.sessionDir(), 'Default'));
    } catch {
      return false;
    }
  }

  onMessage(handler) {
    this.messageHandler = handler;
  }

  setState(state, error = null) {
    this.state = state;
    this.error = error;
    this.since = Date.now();
    if (state !== 'qr') { this.qrDataUrl = null; this.qrAt = null; }
    console.log(`[whatsapp] state: ${state}${error ? ` (${error})` : ''}`);
  }

  getStatus() {
    return {
      enabled: this.isEnabled(),
      state: this.state,
      qr: this.state === 'qr' ? this.qrDataUrl : null,
      qrAt: this.qrAt,
      number: this.info?.wid?.user || null,
      name: this.info?.pushname || null,
      since: this.since,
      error: this.error,
      hasSavedSession: this.hasSavedSession(),
      stats: this.stats,
    };
  }

  isReady() {
    return this.state === 'ready' && Boolean(this.client);
  }

  botNumber() {
    return this.isReady() ? this.info?.wid?.user || null : null;
  }

  later(fn, ms) {
    const t = setTimeout(() => { this.timers.delete(t); fn(); }, ms);
    t.unref?.();
    this.timers.add(t);
    return t;
  }

  clearTimers() {
    this.timers.forEach(clearTimeout);
    this.timers.clear();
  }

  // Chrome refuses to open a profile it thinks another Chrome still owns. After a crash or a hard
  // kill that lock is stale, and it is safe to clear because nothing of ours is running.
  clearStaleLocks() {
    for (const name of ['SingletonLock', 'SingletonCookie', 'SingletonSocket']) {
      try { fs.rmSync(path.join(this.sessionDir(), name), { force: true }); } catch { /* nothing to clear */ }
    }
  }

  lockFile() {
    return path.join(this.sessionRoot(), 'formos-whatsapp.lock');
  }

  // Only one server process may drive the saved WhatsApp login. Two browsers on one profile corrupt it and
  // make WhatsApp drop the connection again and again, so a second process refuses to start.
  acquireLock() {
    fs.mkdirSync(this.sessionRoot(), { recursive: true });
    let owner = null;
    try { owner = parseInt(fs.readFileSync(this.lockFile(), 'utf8'), 10); } catch { /* no lock yet */ }
    if (owner && owner !== process.pid) {
      let alive = true;
      try { process.kill(owner, 0); } catch (error) { alive = error.code === 'EPERM'; }
      if (alive) {
        throw Object.assign(new Error(`WhatsApp is already running in another FormOS server (process ${owner}). Stop that one first.`), { code: 'LOCKED' });
      }
    }
    fs.writeFileSync(this.lockFile(), String(process.pid));
    this.lockHeld = true;
  }

  releaseLock() {
    if (!this.lockHeld) return;
    this.lockHeld = false;
    try {
      if (parseInt(fs.readFileSync(this.lockFile(), 'utf8'), 10) === process.pid) fs.rmSync(this.lockFile(), { force: true });
    } catch { /* already gone */ }
  }

  // A browser left over from a crashed or killed server still holds the profile. With the lock ours, any
  // browser using this profile is an orphan, so it is closed before a new one starts.
  killOrphans() {
    if (process.platform === 'win32') return;
    try { execFileSync('pkill', ['-f', '--', `--user-data-dir=${this.sessionDir()}`], { stdio: 'ignore' }); } catch { /* none running */ }
  }

  killBrowserNow() {
    try { this.client?.pupBrowser?.process()?.kill('SIGKILL'); } catch { /* already closed */ }
  }

  // The WhatsApp Web library sometimes rejects a promise nobody awaits (for example when WhatsApp Web
  // reloads its page). That must not take the whole server down. Returns true when it was handled here.
  absorbLibraryError(reason) {
    const text = `${reason?.stack || reason?.message || reason}`;
    if (!/whatsapp-web\.js|puppeteer/i.test(text)) return false;
    console.warn(`[whatsapp] ignored an internal library error: ${String(reason?.message || reason).split('\n')[0]}`);
    this.stats.lastError = String(reason?.message || reason).split('\n')[0].slice(0, 200);
    return true;
  }

  async start() {
    if (!this.isEnabled()) throw new Error('WhatsApp is switched off on this server.');
    if (['starting', 'qr', 'authenticating', 'ready'].includes(this.state)) return;

    try {
      this.acquireLock();
    } catch (error) {
      this.wanted = false;
      this.setState('failed', error.message);
      throw error;
    }
    const { Client, LocalAuth } = require('whatsapp-web.js');
    this.wanted = true;
    this.setState('starting');
    this.killOrphans();
    await new Promise((resolve) => setTimeout(resolve, 400));
    this.clearStaleLocks();

    const args = ['--disable-dev-shm-usage', '--disable-gpu', '--no-first-run'];
    if (process.env.WHATSAPP_NO_SANDBOX === 'true' || (typeof process.getuid === 'function' && process.getuid() === 0)) {
      args.push('--no-sandbox', '--disable-setuid-sandbox');
    }

    // If WhatsApp changes its web page and something breaks (for example file downloads), a known-good page version
    // can be pinned with WHATSAPP_WEB_VERSION_URL (an html file such as one from github.com/wppconnect-team/wa-version).
    const webVersionCache = process.env.WHATSAPP_WEB_VERSION_URL ? { webVersionCache: { type: 'remote', remotePath: process.env.WHATSAPP_WEB_VERSION_URL } } : {};
    const client = new Client({
      ...webVersionCache,
      authStrategy: new LocalAuth({ clientId: CLIENT_ID, dataPath: this.sessionRoot() }),
      puppeteer: {
        headless: true,
        args,
        ...(process.env.PUPPETEER_EXECUTABLE_PATH ? { executablePath: process.env.PUPPETEER_EXECUTABLE_PATH } : {}),
      },
    });
    this.client = client;

    client.on('qr', async (qr) => {
      if (this.client !== client) return;
      try {
        this.qrDataUrl = await QRCode.toDataURL(qr, { width: 320, margin: 1, errorCorrectionLevel: 'M' });
        this.qrAt = Date.now();
        this.state = 'qr';
        this.error = null;
        this.since = this.since || Date.now();
        console.log('[whatsapp] QR ready to scan');
      } catch (error) {
        console.error('[whatsapp] could not draw the QR code:', error.message);
      }
    });
    client.on('authenticated', () => { if (this.client === client) { this.setState('authenticating'); } });
    client.on('ready', () => {
      if (this.client !== client) return;
      this.info = client.info || null;
      this.reconnectAttempt = 0;
      this.setState('ready');
      console.log(`[whatsapp] ready as +${this.info?.wid?.user || 'unknown'}`);
    });
    client.on('auth_failure', (message) => {
      if (this.client !== client) return;
      this.setState('failed', `Sign-in was rejected: ${message || 'unknown reason'}`);
      this.teardown(client);
    });
    client.on('disconnected', (reason) => {
      if (this.client !== client) return;
      console.warn(`[whatsapp] disconnected: ${reason}`);
      this.teardown(client);
      if (String(reason).toUpperCase() === 'LOGOUT') {
        // The phone removed this linked device, so the saved login no longer works.
        this.forgetSession();
        this.wanted = false;
        this.info = null;
        this.setState('logged_out', 'The linked device was removed from the phone. Connect again and scan a new code.');
        return;
      }
      this.setState('failed', `Connection lost: ${reason}`);
      this.scheduleReconnect();
    });
    client.on('message', (msg) => this.dispatch(msg));

    // A start that never reaches a QR code or a login is stuck (blocked network, broken Chrome).
    this.later(() => {
      if (this.client === client && this.state === 'starting') {
        this.setState('failed', 'WhatsApp Web did not respond in time. Check the server\'s internet access.');
        this.teardown(client);
        this.scheduleReconnect();
      }
    }, STALE_START_MS);

    client.initialize().catch((error) => {
      if (this.client !== client) return;
      this.setState('failed', `Could not start: ${error.message}`);
      this.teardown(client);
      this.scheduleReconnect();
    });
  }

  async dispatch(msg) {
    try {
      const id = msg?.id?._serialized;
      if (id) {
        if (this.seen.has(id)) return;
        this.seen.add(id);
        if (this.seen.size > 500) this.seen.delete(this.seen.values().next().value);
      }
      if (!this.messageHandler) return;
      await this.messageHandler(msg, this);
    } catch (error) {
      console.error('[whatsapp] message handler failed:', error.message);
    }
  }

  scheduleReconnect() {
    if (!this.wanted || !this.isEnabled()) return;
    const wait = RECONNECT_STEPS_MS[Math.min(this.reconnectAttempt, RECONNECT_STEPS_MS.length - 1)];
    this.reconnectAttempt += 1;
    console.log(`[whatsapp] reconnecting in ${Math.round(wait / 1000)}s`);
    this.later(() => {
      if (this.wanted && ['failed', 'stopped'].includes(this.state)) this.start().catch((e) => console.error('[whatsapp] reconnect failed:', e.message));
    }, wait);
  }

  async teardown(client) {
    if (this.client === client) this.client = null;
    try {
      await Promise.race([client.destroy(), new Promise((resolve) => setTimeout(resolve, 8000))]);
    } catch { /* the browser may already be gone */ }
    try { client.pupBrowser?.process()?.kill('SIGKILL'); } catch { /* closed */ }
  }

  forgetSession() {
    try { fs.rmSync(this.sessionDir(), { recursive: true, force: true }); } catch (error) {
      console.error('[whatsapp] could not remove the saved session:', error.message);
    }
  }

  // Stops the bot. With forget, it also signs the device out of WhatsApp and deletes the saved login,
  // so the next start needs a new QR scan.
  async stop({ forget = false } = {}) {
    this.wanted = false;
    this.clearTimers();
    const client = this.client;
    if (client) {
      if (forget && this.state === 'ready') {
        try { await Promise.race([client.logout(), new Promise((resolve) => setTimeout(resolve, 8000))]); } catch { /* removed below anyway */ }
      }
      await this.teardown(client);
    }
    if (forget) { this.forgetSession(); this.info = null; }
    this.releaseLock();
    this.setState('stopped');
    this.reconnectAttempt = 0;
  }

  async restart() {
    await this.stop();
    await this.start();
  }

  // The phone number behind a chat id. New WhatsApp accounts are addressed by an opaque "@lid" id whose
  // digits are NOT a phone number, so those are translated by WhatsApp itself. Returns digits or null.
  async phoneFor(chatId, msg) {
    if (typeof chatId !== 'string') return null;
    if (chatId.endsWith('@c.us')) return chatId.replace('@c.us', '').replace(/\D/g, '') || null;
    const looksLikePhone = (n) => /^\d{10,15}$/.test(n) && n !== chatId.replace(/\D/g, '');
    try {
      if (this.client?.getContactLidAndPhone) {
        const [found] = (await this.client.getContactLidAndPhone([chatId])) || [];
        const pn = String(found?.pn || '').replace(/\D/g, '');
        if (looksLikePhone(pn)) return pn;
      }
    } catch { /* try the contact next */ }
    try {
      const contact = await msg?.getContact?.();
      const n = String(contact?.number || contact?.id?.user || '').replace(/\D/g, '');
      if (contact?.id?.server === 'c.us' && looksLikePhone(n)) return n;
      if (looksLikePhone(n)) return n;
    } catch { /* unresolved */ }
    return null;
  }

  // Sends are queued with a gap between them, which keeps the account from looking like a spam bot.
  sendText(number, text) {
    const job = this.sendChain.then(async () => {
      if (!this.isReady()) throw Object.assign(new Error('The WhatsApp assistant is not connected right now.'), { code: 'BOT_OFFLINE' });
      const wait = this.lastSendAt + MIN_SEND_GAP_MS - Date.now();
      if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
      const id = await this.client.getNumberId(String(number));
      if (!id) throw Object.assign(new Error('That number is not on WhatsApp.'), { code: 'NOT_ON_WHATSAPP' });
      const sent = await this.client.sendMessage(id._serialized, text);
      this.lastSendAt = Date.now();
      return sent;
    });
    this.sendChain = job.catch(() => {});
    return job;
  }

  async isOnWhatsApp(number) {
    if (!this.isReady()) throw Object.assign(new Error('The WhatsApp assistant is not connected right now.'), { code: 'BOT_OFFLINE' });
    return Boolean(await this.client.getNumberId(String(number)));
  }

  // Reconnects on server start, but only when a login is already saved, so a fresh install never
  // opens a browser until an admin asks for it.
  autoStart() {
    if (!this.isEnabled() || process.env.WHATSAPP_AUTOSTART === 'false') return;
    if (!this.hasSavedSession()) { console.log('[whatsapp] no saved session, waiting for an admin to connect'); return; }
    this.start().catch((error) => console.error('[whatsapp] auto start failed:', error.message));
  }
}

module.exports = new WhatsAppService();
