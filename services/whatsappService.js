const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const QRCode = require('qrcode');

const CLIENT_ID = process.env.WHATSAPP_CLIENT_ID || 'formos'; // use a different id on each environment that shares one database
const BACKUP_EVERY_MS = 5 * 60 * 1000;
const LEASE_TTL_MS = 30 * 1000;
const LEASE_RENEW_MS = 10 * 1000;
const STALE_START_MS = 150 * 1000;
// After the saved login is accepted, WhatsApp Web should be ready within a minute or two. Past this it is wedged
// (most often a stale cached WhatsApp Web page), and waiting longer never fixes it.
const STALE_AUTH_MS = 240 * 1000;
// ...and it is given up on sooner when WhatsApp Web reports no loading progress at all for this long.
const STALE_IDLE_MS = 75 * 1000;
const MIN_SEND_GAP_MS = 1200;
const RECONNECT_STEPS_MS = [5000, 15000, 45000, 120000, 300000];

// The one WhatsApp account FormOS sends from. It is linked once by scanning a QR code in the admin
// console. The login is kept in MongoDB (whatsapp-RemoteAuth-<id>.* GridFS collections) and restored into
// a temporary folder on every start and deleted on shutdown, so MongoDB is the only place the login is kept and
// restarts, redeploys and new servers reconnect without a new scan.
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
    // What the admin console shows live: the current step, loading percent and a short plain-language timeline.
    this.progress = { phase: null, percent: null, events: [], nextRetryAt: null };
    this.stuckCount = 0;
    this.lastActivity = Date.now();
    this.leaseId = null;
    this.leaseTimer = null;
    this.wasReady = false;
    this.timers = new Set();
    this.sendChain = Promise.resolve();
    this.lastSendAt = 0;
    this.messageHandler = null;
    this.seen = new Set();
    this.auth = null;
    this.store = null;
    this.savedSession = false;
    // If this process dies, never leave its browser behind holding the saved login.
    process.on('exit', () => { this.killBrowserNow(); });
    // Counts only, never message content: they show an admin whether the assistant is receiving and answering.
    this.stats = { received: 0, answered: 0, ignoredStranger: 0, ignoredOther: 0, unresolved: 0, failed: 0, lastReceivedAt: null, lastAnsweredAt: null, lastError: null };
  }

  isEnabled() {
    return process.env.WHATSAPP_ENABLED !== 'false';
  }

  // Scratch space shared by every FormOS process on this machine (only holds the downloaded WhatsApp Web page).
  scratchBase() {
    return path.resolve(process.env.WHATSAPP_SESSION_DIR || path.join(os.tmpdir(), 'formos-whatsapp'));
  }

  // This process's own working folder. Each server process gets its own, so a second server (or one that is still
  // shutting down) never wipes or corrupts the browser profile another one is using.
  sessionRoot() {
    return path.join(this.scratchBase(), `p${process.pid}`);
  }

  // Working folders left behind by processes that no longer exist (a crash or a hard kill).
  removeDeadWorkingFolders() {
    let names = [];
    try { names = fs.readdirSync(this.scratchBase()); } catch { return; }
    for (const name of names) {
      const pid = /^p(\d+)$/.exec(name)?.[1];
      if (!pid || Number(pid) === process.pid) continue;
      let alive = true;
      try { process.kill(Number(pid), 0); } catch (error) { alive = error.code === 'EPERM'; }
      if (!alive) try { fs.rmSync(path.join(this.scratchBase(), name), { recursive: true, force: true }); } catch { /* in use or gone */ }
    }
  }

  // The working copy of the browser profile. It is rebuilt from MongoDB on every start.
  sessionDir() {
    return path.join(this.sessionRoot(), `RemoteAuth-${CLIENT_ID}`);
  }

  // Places an older disk-based setup (LocalAuth) kept its login. It is copied into MongoDB once and then deleted.
  legacyDirs() {
    const roots = [process.env.WHATSAPP_SESSION_DIR, path.join(__dirname, '..', '.wwebjs_auth'), '/data/whatsapp'].filter(Boolean).map((r) => path.resolve(r));
    return [...new Set(roots)].map((r) => path.join(r, `session-${CLIENT_ID}`)).filter((d) => fs.existsSync(path.join(d, 'Default')));
  }

  removeLegacyCopies() {
    for (const dir of this.legacyDirs()) {
      try { fs.rmSync(dir, { recursive: true, force: true }); console.log('[whatsapp] removed the old on-disk login, it now lives only in MongoDB'); } catch (error) {
        console.error('[whatsapp] could not remove the old on-disk login:', error.message);
      }
    }
  }

  sessionStore() {
    if (!this.store) {
      const mongoose = require('mongoose');
      const WhatsAppMongoStore = require('./whatsappMongoStore');
      this.store = new WhatsAppMongoStore({ mongoose, dataPath: this.sessionRoot() });
    }
    return this.store;
  }

  // The saved login lives in MongoDB, so nothing can start (or even tell whether a login exists) before it is connected.
  async waitForMongo(timeoutMs = 60000) {
    const mongoose = require('mongoose');
    if (mongoose.connection.readyState === 1) return true;
    return new Promise((resolve) => {
      const done = (ok) => { clearTimeout(timer); mongoose.connection.off('open', onOpen); resolve(ok); };
      const onOpen = () => done(true);
      const timer = setTimeout(() => done(false), timeoutMs);
      mongoose.connection.on('open', onOpen);
    });
  }

  async refreshSavedSession() {
    try {
      if (!(await this.waitForMongo())) throw new Error('MongoDB is not connected');
      this.savedSession = await this.sessionStore().sessionExists({ session: `RemoteAuth-${CLIENT_ID}` });
    } catch (error) {
      console.error(`[whatsapp] could not check for a saved login: ${error.message}`);
      throw error;
    }
    return this.savedSession;
  }

  hasSavedSession() {
    return this.savedSession;
  }

  onMessage(handler) {
    this.messageHandler = handler;
  }

  // Records a step for the live progress feed. Plain wording only: this is shown to admins (and a one-line summary
  // to members), so no paths, ids or page contents go in here.
  note(text, phase = null, percent = undefined, key = null) {
    // A late loading update must not pull the step back once sign-in has moved on.
    const later = ['syncing', 'ready', 'saving', 'saved'].includes(this.progress.phase);
    if (phase && !(key === 'loading' && later)) this.progress.phase = phase;
    if (percent !== undefined && !(key === 'loading' && later)) this.progress.percent = percent;
    const events = this.progress.events;
    const last = events[events.length - 1];
    if (last && last.text === text) return;
    // Repeating steps (loading 12%, 13%, ...) update one line instead of filling the timeline.
    if (key && last && last.key === key) { last.text = text; last.at = Date.now(); return; }
    events.push({ at: Date.now(), text, ...(key ? { key } : {}) });
    if (events.length > 25) events.shift();
  }

  setState(state, error = null) {
    this.state = state;
    this.error = error;
    this.since = Date.now();
    if (state !== 'qr') { this.qrDataUrl = null; this.qrAt = null; }
    if (state === 'ready' || state === 'stopped' || state === 'logged_out') this.progress.nextRetryAt = null;
    if (state === 'stopped') { this.progress.phase = null; this.progress.percent = null; }
    if (state === 'failed' && error) this.note(error, 'failed');
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
      progress: { ...this.progress, events: this.progress.events.slice(-12), attempt: this.stuckCount + 1 },
      stats: this.stats,
    };
  }

  // The one-line version members see when the assistant is not answering yet. No timeline, no technical detail.
  publicProgress() {
    const { phase, percent, nextRetryAt } = this.progress;
    if (this.state === 'ready' || this.state === 'stopped' || !this.wanted && this.state !== 'starting') return { phase: null, percent: null, retryAt: null };
    const text = {
      waiting_previous: 'Waiting for the previous session to finish saving',
      restoring: 'Restoring the saved login',
      opening: 'Opening WhatsApp',
      loading: 'Loading WhatsApp',
      syncing: 'Signing in and syncing',
      retrying: 'Reconnecting',
      qr: 'Waiting for the account to be linked',
    }[phase] || 'Connecting';
    return { phase: text, percent: phase === 'loading' ? percent : null, retryAt: nextRetryAt };
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

  webCacheDir() {
    return path.join(this.scratchBase(), 'web-cache');
  }

  // The WhatsApp Web page the library saved from an earlier run. When WhatsApp updates its site, a stale copy lets the
  // login succeed but never finishes loading, so it is thrown away and fetched fresh. The saved login is not touched.
  clearWebCache() {
    try { fs.rmSync(this.webCacheDir(), { recursive: true, force: true }); console.log('[whatsapp] cleared the cached WhatsApp Web page'); } catch (error) {
      console.error('[whatsapp] could not clear the cached page:', error.message);
    }
  }

  // Gives up on a start that is stuck in `state`, closes its browser and tries again. From the second stuck attempt in
  // a row the cached page is cleared too. Each new start rebuilds the browser profile from the copy in MongoDB.
  // What the WhatsApp Web page looks like right now, so a hang can be diagnosed from the log instead of guessed at.
  async stuckReport(client) {
    const page = client.pupPage;
    if (!page) return 'no browser page';
    const probe = await Promise.race([
      page.evaluate(() => {
        const out = {};
        try { const socket = window.require('WAWebSocketModel').Socket; out.socketState = socket.state; out.hasSynced = socket.hasSynced; } catch (e) { out.socketError = String(e).slice(0, 80); }
        out.helperInjected = typeof window.WWebJS !== 'undefined';
        out.waVersion = window.Debug && window.Debug.VERSION;
        out.page = (document.body && document.body.innerText || '').replace(/\s+/g, ' ').slice(0, 220);
        return out;
      }).catch((e) => ({ probeError: String(e.message || e).slice(0, 120) })),
      new Promise((resolve) => setTimeout(() => resolve({ probeError: 'page did not answer in 6s' }), 6000)),
    ]);
    let shot = '';
    try {
      const file = path.join(this.scratchBase(), 'whatsapp-stuck.png');
      fs.mkdirSync(this.scratchBase(), { recursive: true });
      await Promise.race([page.screenshot({ path: file }), new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 6000))]);
      shot = ` screenshot=${file}`;
    } catch { /* the page may be gone */ }
    return `${JSON.stringify(probe)}${shot}`;
  }

  watchStuck(client, state, idleMs, maxMs, reason) {
    const began = Date.now();
    this.lastActivity = Date.now();
    // The page can be fully loaded, synced and injected while the library never reports ready (seen with the
    // "What's new" popup showing). Reloading the page re-runs the library's start-up and fixes it, and a normal start
    // is ready within a few seconds of sign-in, so it is reloaded early: after 15s of quiet, and once more after 30s.
    let reloads = 0;
    const RELOAD_AFTER_MS = [15000, 30000];
    const check = async () => {
      if (this.client !== client || this.state !== state) return;
      const idle = Date.now() - this.lastActivity;
      if (state === 'authenticating' && reloads < RELOAD_AFTER_MS.length && idle >= RELOAD_AFTER_MS[reloads] && client.pupPage) {
        reloads += 1;
        console.warn(`[whatsapp] no progress for ${Math.round(idle / 1000)}s, page report: ${await this.stuckReport(client)}`);
        console.warn(`[whatsapp] reloading the WhatsApp Web page (${reloads}/${RELOAD_AFTER_MS.length})`);
        this.note(`Finishing up is taking longer than usual (${Math.round(idle / 1000)}s). Reloading WhatsApp Web.`, 'retrying');
        this.lastActivity = Date.now();
        client.pupPage.reload({ waitUntil: 'load', timeout: 60000 }).catch((e) => console.warn(`[whatsapp] page reload failed: ${e.message}`));
        this.later(check, 3000);
        return;
      }
      if (idle < idleMs && Date.now() - began < maxMs) { this.later(check, 5000); return; }
      console.warn(`[whatsapp] still stuck, page report: ${await this.stuckReport(client)}`);
      if (this.client !== client || this.state !== state) return;
      this.stuckCount += 1;
      this.note(`Still no progress. Restarting the connection (attempt ${this.stuckCount}).`, 'retrying');
      this.setState('failed', reason);
      this.teardown(client);
      if (this.stuckCount >= 2) this.clearWebCache();
      // The newest backup may have been taken at a bad moment. After two hangs try the one before it, then alternate.
      this.sessionStore().preferOlder = this.stuckCount % 4 >= 2;
      if (this.sessionStore().preferOlder) { console.warn('[whatsapp] next attempt restores the previous backup of the login'); this.note('The next attempt uses the previous backup of the login.'); }
      this.scheduleReconnect();
    };
    this.later(check, 5000);
  }

  // A browser left over from an earlier start of this same process still holds its profile folder, so it is
  // closed before a new one starts. Other servers use their own folders and are not touched.
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

  // First start after moving from disk to MongoDB: upload the login that is already on disk so nobody has to scan again.
  async migrateLegacySession(RemoteAuth) {
    const session = `RemoteAuth-${CLIENT_ID}`;
    if (await this.sessionStore().sessionExists({ session })) { this.removeLegacyCopies(); return; }
    const [legacy] = this.legacyDirs();
    if (!legacy) return;
    console.log('[whatsapp] moving the saved login from disk to MongoDB');
    const auth = new RemoteAuth({ clientId: CLIENT_ID, dataPath: this.sessionRoot(), store: this.sessionStore(), backupSyncIntervalMs: BACKUP_EVERY_MS });
    auth.userDataDir = legacy;
    auth.sessionName = session;
    await auth.storeRemoteSession();
    // Only delete the disk copy once MongoDB is confirmed to hold the login.
    if (await this.sessionStore().sessionExists({ session })) { console.log('[whatsapp] login saved in MongoDB'); this.removeLegacyCopies(); }
  }

  async start() {
    if (!this.isEnabled()) throw new Error('WhatsApp is switched off on this server.');
    if (['starting', 'qr', 'authenticating', 'ready'].includes(this.state)) return;

    this.removeDeadWorkingFolders();
    fs.mkdirSync(this.sessionRoot(), { recursive: true });
    const { Client, RemoteAuth } = require('whatsapp-web.js');
    require('./whatsappPatches').applyWhatsAppPatches();
    this.wanted = true;
    this.progress.percent = null;
    this.note('Starting the assistant.', 'starting');
    this.setState('starting');
    try {
      if (!(await this.waitForMongo())) throw new Error('MongoDB is not connected');
      await this.acquireLease();
      this.note('Restoring the saved login from the database.', 'restoring');
      await this.migrateLegacySession(RemoteAuth);
      await this.refreshSavedSession();
    } catch (error) {
      this.wanted = false;
      this.setState('failed', `Could not reach the saved login in MongoDB: ${error.message}`);
      await this.releaseLease();
      throw error;
    }
    this.note('Opening WhatsApp Web.', 'opening');
    this.killOrphans();
    await new Promise((resolve) => setTimeout(resolve, 400));
    this.clearStaleLocks();

    const args = ['--disable-dev-shm-usage', '--disable-gpu', '--no-first-run'];
    if (process.env.WHATSAPP_NO_SANDBOX === 'true' || (typeof process.getuid === 'function' && process.getuid() === 0)) {
      args.push('--no-sandbox', '--disable-setuid-sandbox');
    }

    // If WhatsApp changes its web page and something breaks (for example file downloads), a known-good page version
    // can be pinned with WHATSAPP_WEB_VERSION_URL (an html file such as one from github.com/wppconnect-team/wa-version).
    const webVersionCache = { webVersionCache: process.env.WHATSAPP_WEB_VERSION_URL
      ? { type: 'remote', remotePath: process.env.WHATSAPP_WEB_VERSION_URL }
      : { type: 'local', path: this.webCacheDir() } };
    this.wasReady = false;
    const startedAt = Date.now();
    this.auth = new RemoteAuth({ clientId: CLIENT_ID, dataPath: this.sessionRoot(), store: this.sessionStore(), backupSyncIntervalMs: BACKUP_EVERY_MS });
    // Chrome compacts its database files in the background, so a file can vanish while the backup is copying it
    // (ENOENT). That is harmless to retry a moment later, and the periodic backups use this same method.
    const save = this.auth.storeRemoteSession.bind(this.auth);
    this.auth.storeRemoteSession = async (options) => {
      for (let attempt = 1; ; attempt++) {
        try { return await save(options); } catch (error) {
          if (attempt >= 4) throw error;
          console.warn(`[whatsapp] login backup attempt ${attempt} failed (${error.message.split('\n')[0].slice(0, 120)}), retrying`);
          await new Promise((resolve) => setTimeout(resolve, 1500 * attempt));
        }
      }
    };
    const client = new Client({
      ...webVersionCache,
      authStrategy: this.auth,
      puppeteer: {
        headless: true,
        args,
        // Puppeteer would kill Chrome the instant Ctrl+C / a deploy signal arrives, before the login could be saved to
        // MongoDB. FormOS closes the browser itself (see stop) after saving.
        handleSIGINT: false,
        handleSIGTERM: false,
        handleSIGHUP: false,
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
        this.note('Waiting for the QR code to be scanned.', 'qr');
        console.log('[whatsapp] QR ready to scan');
      } catch (error) {
        console.error('[whatsapp] could not draw the QR code:', error.message);
      }
    });
    client.on('authenticated', () => {
      if (this.client !== client) return;
      this.lastActivity = Date.now();
      this.note('WhatsApp accepted the login. Syncing and getting ready.', 'syncing');
      this.setState('authenticating');
      this.watchStuck(client, 'authenticating', STALE_IDLE_MS, STALE_AUTH_MS, 'WhatsApp accepted the login but did not finish loading in time. Retrying.');
    });
    client.on('ready', () => {
      if (this.client !== client) return;
      this.info = client.info || null;
      this.reconnectAttempt = 0;
      this.stuckCount = 0;
      this.sessionStore().preferOlder = false;
      this.wasReady = true;
      this.note(`Connected${this.client?.info?.wid?.user ? ` as +${this.client.info.wid.user}` : ''} after ${Math.round((Date.now() - startedAt) / 1000)}s.`, 'ready', 100);
      console.log(`[whatsapp] ready after ${Math.round((Date.now() - startedAt) / 1000)}s`);
      this.setState('ready');
      if (!this.savedSession) console.log('[whatsapp] the login is saved to MongoDB about a minute after connecting; keep the server running until you see "login saved in MongoDB"');
      console.log(`[whatsapp] ready as +${this.info?.wid?.user || 'unknown'}`);
    });
    client.on('auth_failure', (message) => {
      if (this.client !== client) return;
      this.setState('failed', `Sign-in was rejected: ${message || 'unknown reason'}`);
      this.teardown(client);
    });
    client.on('disconnected', async (reason) => {
      if (this.client !== client) return;
      console.warn(`[whatsapp] disconnected: ${reason}`);
      this.note(`The connection dropped (${String(reason).slice(0, 60)}).`, 'failed');
      this.teardown(client);
      if (String(reason).toUpperCase() === 'LOGOUT') {
        // The phone removed this linked device, so the saved login no longer works.
        await this.forgetSession();
        this.wanted = false;
        this.info = null;
        this.setState('logged_out', 'The linked device was removed from the phone. Connect again and scan a new code.');
        return;
      }
      this.setState('failed', `Connection lost: ${reason}`);
      this.scheduleReconnect();
    });
    client.on('loading_screen', (percent, message) => {
      if (this.client !== client) return;
      this.lastActivity = Date.now();
      this.note(`Loading WhatsApp, ${percent}%.`, 'loading', Number(percent), 'loading');
      console.log(`[whatsapp] loading ${percent}%${message ? ` - ${message}` : ''}`);
    });
    client.on('change_state', (change) => { if (this.client === client) { this.lastActivity = Date.now(); console.log(`[whatsapp] connection: ${change}`); } });
    client.on('remote_session_saved', () => { this.savedSession = true; this.note('Login saved to the database. It will survive restarts.', 'saved'); console.log('[whatsapp] login saved in MongoDB'); });
    client.on('message', (msg) => this.dispatch(msg));

    // A start that never reaches a QR code or a login is stuck (blocked network, broken Chrome).
    this.watchStuck(client, 'starting', STALE_START_MS, STALE_START_MS, 'WhatsApp Web did not respond in time. Check the server\'s internet access.');

    const hookPage = () => {
      const page = client.pupPage;
      if (!page || page.__formosHooked) return;
      page.__formosHooked = true;
      page.on('pageerror', (error) => console.warn(`[whatsapp] page error: ${String(error.message || error).split('\n')[0].slice(0, 200)}`));
      page.on('requestfailed', (request) => { if (/whatsapp|wa\.me|fbcdn/i.test(request.url())) console.warn(`[whatsapp] request failed: ${request.failure()?.errorText} ${request.url().slice(0, 100)}`); });
    };
    const hookTimer = setInterval(() => { hookPage(); if (client.pupPage?.__formosHooked || this.client !== client) clearInterval(hookTimer); }, 500);
    hookTimer.unref?.();

    client.initialize().catch((error) => {
      if (this.client !== client) return;
      this.setState('failed', `Could not start: ${error.message}`);
      this.teardown(client);
      this.scheduleReconnect();
    });
  }

  async dispatch(msg) {
    try {
      require('./whatsappPatches').normalizeMessageId(msg);
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
    this.progress.nextRetryAt = Date.now() + wait;
    this.note(`Reconnecting in ${Math.round(wait / 1000)}s.`, 'retrying');
    console.log(`[whatsapp] reconnecting in ${Math.round(wait / 1000)}s`);
    this.later(() => {
      if (this.wanted && ['failed', 'stopped'].includes(this.state)) this.start().catch((e) => console.error('[whatsapp] reconnect failed:', e.message));
    }, wait);
  }

  // Writes the current login to MongoDB now, instead of waiting for the next scheduled backup.
  async flushSession(timeoutMs = 25000) {
    if (!this.auth || !this.wasReady) return false;
    this.note('Saving the login to the database.', 'saving');
    try {
      await Promise.race([
        this.auth.storeRemoteSession({ emit: true }),
        new Promise((_, reject) => setTimeout(() => reject(new Error('timed out')), timeoutMs)),
      ]);
      return true;
    } catch (error) {
      console.error('[whatsapp] could not save the login to MongoDB:', error.message);
      return false;
    }
  }

  // ---- hand-off between servers ---------------------------------------------------------------------------------
  // WhatsApp lets only one browser use a login at a time, and a new server restores the login from MongoDB. So a new
  // server must wait until the old one has finished its final save and closed its browser, otherwise it restores a
  // stale copy and fights the old browser for the login. The running server holds a short lease in MongoDB and renews
  // it; a stopping server releases it after saving. A server that crashed stops renewing, so its lease simply expires.
  leases() {
    return require('mongoose').connection.db.collection('whatsapp_leases');
  }

  async acquireLease(maxWaitMs = 45000) {
    if (!this.leaseId) this.leaseId = `${os.hostname()}:${process.pid}:${Math.random().toString(36).slice(2, 8)}`;
    const claim = () => this.leases().findOneAndUpdate(
      { _id: CLIENT_ID, $or: [{ holder: this.leaseId }, { expiresAt: { $lt: new Date() } }] },
      { $set: { holder: this.leaseId, expiresAt: new Date(Date.now() + LEASE_TTL_MS) } },
      { upsert: true },
    );
    const deadline = Date.now() + maxWaitMs;
    let announced = false;
    for (;;) {
      try { await claim(); break; } catch (error) {
        if (error.code !== 11000) throw error; // 11000: someone else holds a lease that has not expired yet
        if (Date.now() >= deadline) {
          console.warn('[whatsapp] the other server did not hand over in time, taking over');
          this.note('The other server did not hand over in time, taking over.');
          await this.leases().updateOne({ _id: CLIENT_ID }, { $set: { holder: this.leaseId, expiresAt: new Date(Date.now() + LEASE_TTL_MS) } }, { upsert: true });
          break;
        }
        if (!announced) { announced = true; this.note('Another server is still closing WhatsApp. Waiting for it to finish saving the login.', 'waiting_previous'); console.log('[whatsapp] another server is still closing WhatsApp, waiting for it to finish saving'); }
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }
    clearInterval(this.leaseTimer);
    this.leaseTimer = setInterval(() => {
      this.leases().updateOne({ _id: CLIENT_ID, holder: this.leaseId }, { $set: { expiresAt: new Date(Date.now() + LEASE_TTL_MS) } }).catch(() => {});
    }, LEASE_RENEW_MS);
    this.leaseTimer.unref?.();
  }

  async releaseLease() {
    clearInterval(this.leaseTimer);
    this.leaseTimer = null;
    if (!this.leaseId) return;
    try { await this.leases().deleteOne({ _id: CLIENT_ID, holder: this.leaseId }); } catch { /* it expires on its own */ }
  }

  // Closes the browser. Returns true when it shut down by itself (its files are then complete); false when it had to
  // be force-killed, in which case its database files may be half written.
  async teardown(client) {
    if (this.client === client) this.client = null;
    let clean = false;
    try {
      await Promise.race([client.destroy().then(() => { clean = true; }), new Promise((resolve) => setTimeout(resolve, 15000))]);
    } catch { /* the browser may already be gone */ }
    try { client.pupBrowser?.process()?.kill('SIGKILL'); } catch { /* closed */ }
    return clean;
  }

  // The temporary browser profile and its leftovers. MongoDB keeps the login, so none of this is needed once stopped.
  removeWorkingFiles() {
    try { fs.rmSync(this.sessionDir(), { recursive: true, force: true }); } catch (error) {
      console.error('[whatsapp] could not remove the temporary session folder:', error.message);
    }
    try { fs.rmSync(path.join(this.sessionRoot(), `RemoteAuth-${CLIENT_ID}.zip`), { force: true }); } catch { /* none */ }
  }

  // Removes the saved login everywhere (MongoDB, the working profile and any old disk copy), so the next start needs a scan.
  async forgetSession() {
    this.removeWorkingFiles();
    this.removeLegacyCopies();
    try { await this.sessionStore().delete({ session: `RemoteAuth-${CLIENT_ID}` }); } catch (error) {
      console.error('[whatsapp] could not remove the saved login from MongoDB:', error.message);
    }
    this.savedSession = false;
  }

  // Stops the bot. With forget, it also signs the device out of WhatsApp and deletes the saved login,
  // so the next start needs a new QR scan.
  async stop({ forget = false } = {}) {
    this.wanted = false;
    this.clearTimers();
    const client = this.client;
    if (client && forget && this.state === 'ready') {
      try { await Promise.race([client.logout(), new Promise((resolve) => setTimeout(resolve, 8000))]); } catch { /* removed below anyway */ }
    }
    // Close the browser first: it then flushes its files and stops changing them, so the copy saved to MongoDB is
    // complete. This runs whatever the connection state was, because the profile's files are still valid on disk.
    const closedCleanly = client ? await this.teardown(client) : true;
    if (!forget) {
      if (closedCleanly) await this.flushSession();
      else console.warn('[whatsapp] the browser had to be force-closed, keeping the previous login backup instead of saving a possibly damaged one');
      this.wasReady = false;
    }
    if (forget) { await this.forgetSession(); this.info = null; } else this.removeWorkingFiles();
    try { fs.rmSync(this.sessionRoot(), { recursive: true, force: true }); } catch { /* already gone */ }
    await this.releaseLease(); // last, so the next server restores the login saved just above
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

  // Sends a file (photo or PDF) to one number, in the same queue as text so sends keep their gap.
  sendMedia(number, { buffer, mimeType, filename }, caption) {
    const { MessageMedia } = require('whatsapp-web.js');
    const job = this.sendChain.then(async () => {
      if (!this.isReady()) throw Object.assign(new Error('The WhatsApp assistant is not connected right now.'), { code: 'BOT_OFFLINE' });
      const wait = this.lastSendAt + MIN_SEND_GAP_MS - Date.now();
      if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
      const id = await this.client.getNumberId(String(number));
      if (!id) throw Object.assign(new Error('That number is not on WhatsApp.'), { code: 'NOT_ON_WHATSAPP' });
      const media = new MessageMedia(mimeType, buffer.toString('base64'), filename);
      let sent;
      try {
        sent = await this.client.sendMessage(id._serialized, media, { caption });
      } catch (error) {
        // WhatsApp Web sometimes refuses a file sent inline; as a document attachment it goes through.
        sent = await this.client.sendMessage(id._serialized, media, { caption, sendMediaAsDocument: true });
      }
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
  async autoStart() {
    if (!this.isEnabled() || process.env.WHATSAPP_AUTOSTART === 'false') return;
    try {
      await this.refreshSavedSession();
    } catch {
      return; // already logged; an admin can connect from the console once MongoDB is back
    }
    if (!this.savedSession && !this.legacyDirs().length) { console.log('[whatsapp] no saved session, waiting for an admin to connect'); return; }
    this.start().catch((error) => console.error('[whatsapp] auto start failed:', error.message));
  }
}

module.exports = new WhatsAppService();
