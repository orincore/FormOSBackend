require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const mongoose = require('mongoose');
const connectDB = require('./config/database');
const { assertEncryptionConfigured } = require('./services/securityService');

// Refuse to start without the secrets auth depends on; a silent fallback key would
// make every stored authenticator secret unreadable once the environment changes.
if (!process.env.JWT_SECRET) {
  console.error('FATAL: JWT_SECRET is not set');
  process.exit(1);
}
try {
  assertEncryptionConfigured();
} catch (error) {
  console.error(`FATAL: ${error.message}. Set MFA_ENCRYPTION_KEY in the environment.`);
  process.exit(1);
}

const app = express();
const SERVER_START_TIME = Date.now();
let healthPingCount = 0;
let lastHealthPingAt = null;

// Connect to MongoDB
connectDB();

// Trust proxy (required when running behind Render/nginx/load balancers)
app.set('trust proxy', 1);

// Middleware
app.use(helmet());
const ALLOWED_ORIGINS = [
  'http://localhost:3000',
  'http://localhost:3001',
  'https://formos.online',
  'https://www.formos.online',
  'https://api.formos.online',
  ...(process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()) : []),
];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, curl, Postman)
    if (!origin) return callback(null, true);
    // Allow any chrome-extension origin
    if (origin.startsWith('chrome-extension://')) return callback(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    callback(new Error(`CORS: origin ${origin} not allowed`));
  },
  credentials: true,
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/admin', require('./routes/admin'));
app.use('/api/documents', require('./routes/documents'));
app.use('/api/chat', require('./routes/chat'));
app.use('/api/whatsapp', require('./routes/whatsapp'));
app.use('/api/autofill', require('./routes/autofill'));
app.use('/api/form-analyzer', require('./routes/formAnalyzer'));
app.use('/api/eligibility', require('./routes/eligibility'));
app.use('/api/extension', require('./routes/extension'));
app.use('/api/migration', require('./routes/migration'));

// Health check: lightweight keep-alive for Render.com
// - No auth / no rate-limit, fast response for uptime monitors
// - Pings MongoDB to keep connection warm and triggers a self-ping cycle to prevent spin-down
app.get('/health', async (req, res) => {
  healthPingCount += 1;
  lastHealthPingAt = new Date().toISOString();
  const now = Date.now();

  // Lightweight DB liveness check (does not block response on failure)
  let dbStatus = 'unknown';
  let dbLatencyMs = null;
  try {
    const start = Date.now();
    const state = mongoose.connection.readyState; // 0=disconnected 1=connected 2=connecting 3=disconnecting
    if (state === 1 && mongoose.connection.db) {
      await mongoose.connection.db.admin().ping();
      dbLatencyMs = Date.now() - start;
      dbStatus = 'connected';
    } else if (state === 2) {
      dbStatus = 'connecting';
    } else if (state === 0) {
      dbStatus = 'disconnected';
      // Attempt reconnect in background, don't await
      connectDB().catch(() => {});
    } else {
      dbStatus = `state_${state}`;
    }
  } catch (e) {
    dbStatus = 'error';
  }

  // Touch activity so Render sees the instance as active (log + headers prevent caching)
  res.set({
    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0',
  });

  console.log(`[health] ping #${healthPingCount} db=${dbStatus}${dbLatencyMs !== null ? ` ${dbLatencyMs}ms` : ''} uptime=${Math.floor((now - SERVER_START_TIME) / 1000)}s`);

  return res.json({
    status: 'ok',
    message: 'FormOS API is running',
    uptimeSeconds: Math.floor((now - SERVER_START_TIME) / 1000),
    timestamp: new Date().toISOString(),
    pingCount: healthPingCount,
    lastHealthPingAt,
    db: { status: dbStatus, latencyMs: dbLatencyMs },
  });
});

// Alias for monitors that hit /api/health
app.get('/api/health', (req, res) => res.redirect(307, '/health'));

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({
    success: false,
    message: err.message || 'Internal server error'
  });
});

const PORT = process.env.PORT || 5000;

const server = app.listen(PORT, () => {
  console.log(`🚀 FormOS Backend running on port ${PORT}`);
  startSelfPingKeepAlive();

  // Prove the file storage settings work, so a wrong key shows up here and not when someone uploads.
  const { checkStorage, storageProvider } = require('./services/s3Service');
  if (storageProvider() !== 'none') {
    checkStorage().then((r) => {
      if (r.ok) console.log(`[storage] ${r.provider === 'r2' ? 'Cloudflare R2' : 'AWS S3'} is working (bucket ${r.bucket})`);
      else console.error(`[storage] ${r.provider.toUpperCase()} check FAILED while ${r.step}: ${r.message}`);
    });
  } else {
    console.log('[storage] no object storage settings found, files are kept on this server');
  }

  // The WhatsApp assistant reconnects on its own when a login is already saved.
  const whatsapp = require('./services/whatsappService');
  require('./services/whatsappBotService').attach(whatsapp);
  whatsapp.autoStart();

  // Closing the assistant's browser cleanly keeps its saved login from being left locked. nodemon restarts
  // the server with SIGUSR2, so that signal closes the browser too and then lets nodemon carry on.
  let closing = false;
  const shutdown = async (signal) => {
    if (closing) return;
    closing = true;
    console.log(`${signal} received, shutting down`);
    server.close();
    await whatsapp.stop().catch(() => {});
    if (signal === 'SIGUSR2') process.kill(process.pid, 'SIGUSR2');
    else process.exit(0);
  };
  ['SIGINT', 'SIGTERM'].forEach((signal) => process.on(signal, () => shutdown(signal)));
  process.once('SIGUSR2', () => shutdown('SIGUSR2'));

  // An internal error from the WhatsApp library is logged and ignored. Any other unhandled error still
  // stops the server, as it did before.
  const fatal = (kind) => (reason) => {
    if (whatsapp.absorbLibraryError(reason)) return;
    console.error(`${kind}:`, reason);
    process.exit(1);
  };
  process.on('unhandledRejection', fatal('Unhandled promise rejection'));
  process.on('uncaughtException', fatal('Uncaught exception'));
});

// ── Self-ping keep-alive for Render free tier ───────────────────────────────
// Render spins down free services after ~15 min without traffic. While the
// process is awake this interval keeps it warm; once asleep only an external
// pinger (UptimeRobot / cron-job.org / Render health check) can wake it.
// Enable by setting RENDER_EXTERNAL_URL (auto-set by Render) or KEEP_ALIVE_URL.
function startSelfPingKeepAlive() {
  const keepAliveUrl =
    process.env.KEEP_ALIVE_URL ||
    process.env.RENDER_EXTERNAL_URL ||
    (process.env.NODE_ENV === 'production' ? null : null);

  if (!keepAliveUrl) {
    console.log('[keep-alive] disabled, set KEEP_ALIVE_URL or RENDER_EXTERNAL_URL to enable self-ping');
    return;
  }

  const intervalMs = parseInt(process.env.KEEP_ALIVE_INTERVAL_MS || '840000', 10); // 14 min default
  const healthUrl = `${keepAliveUrl.replace(/\/$/, '')}/health`;
  console.log(`[keep-alive] enabled → ${healthUrl} every ${Math.round(intervalMs / 60000)} min`);

  const ping = async () => {
    try {
      const controller = new AbortController();
      const t = setTimeout(() => controller.abort(), 10000);
      const res = await fetch(healthUrl, { signal: controller.signal, headers: { 'User-Agent': 'FormOS-keepalive' } });
      clearTimeout(t);
      console.log(`[keep-alive] ping ${res.status} ${healthUrl}`);
    } catch (e) {
      console.warn(`[keep-alive] ping failed: ${e.message}`);
    }
  };

  // First ping after 2 min so boot can settle, then on interval
  setTimeout(ping, 2 * 60 * 1000);
  setInterval(ping, intervalMs).unref?.();
}
