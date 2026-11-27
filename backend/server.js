// ============================================================
// server.js — Genjutsu Main Entry Point (Cloudflare-ready)
// ============================================================
// Local overrides first (backend/.env.local, never deployed), then .env.
// dotenv never overwrites a value that is already set, so .env.local wins.
require('dotenv').config({ path: require('path').join(__dirname, '.env.local') });
require('dotenv').config();

const express      = require('express');
const session      = require('express-session');
const cors         = require('cors');
const passport     = require('./config/passport');
const path         = require('path');
const pgSession    = require('connect-pg-simple')(session);
const { pool, query, initDB, encryptStoredTokens } = require('./database/db');
const { sealUserTokens } = require('./services/mail/tokens');

const authRoutes          = require('./routes/auth');
const emailRoutes         = require('./routes/emails');
const threatRoutes        = require('./routes/threats');
const honeypotRoutes      = require('./routes/honeypot');
const settingsRoutes      = require('./routes/settings');
const analyticsRoutes     = require('./routes/analytics');
const notificationsRoutes = require('./routes/notifications');
const aiChatRoutes        = require('./routes/aichat');
const accountRoutes       = require('./routes/account');
const { rateLimit }       = require('./middleware/rateLimit');
const { startDigestScheduler } = require('./services/digest');
const adminRoutes         = require('./admin/adminRoutes');

const app  = express();
const PORT = process.env.PORT || 3001;

app.set('trust proxy', 1);

const ALLOWED_ORIGINS = [
  'https://genjutsu.org',
  'https://www.genjutsu.org',
  'https://genjutsu.princemagar338.workers.dev',
  'http://localhost:3001',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://localhost:8787'
];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) callback(null, true);
    else callback(new Error('CORS blocked: ' + origin));
  },
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  store: new pgSession({
    // Same pool, but every session read/write goes through query(), which retries
    // once if Neon is waking up or the connection drops, instead of failing the request
    pool: { query: (text, params) => query(text, params) },
    tableName:             'user_sessions',
    createTableIfMissing:  true,
    pruneSessionInterval:  60 * 60   // prune expired rows every hour
  }),
  secret:            process.env.SESSION_SECRET || 'genjutsu_dev_secret_change_this',
  resave:            false,
  saveUninitialized: false,
  proxy:             true,           // trust X-Forwarded-* from Cloud Run / Cloudflare
  name:              'genjutsu.sid', // explicit name — avoids default 'connect.sid' collisions
  cookie: {
    secure:   process.env.NODE_ENV === 'production', // HTTPS only in prod
    httpOnly: true,
    // sameSite:'none' is REQUIRED for cross-origin requests:
    // browser (genjutsu.org) → Cloudflare Worker → Cloud Run backend
    // Without this the cookie is stripped on every cross-site request,
    // causing the session to appear lost on every page refresh.
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge:   7 * 24 * 60 * 60 * 1000  // 7 days
  }
}));

// Sessions created before token encryption: seal their tokens on the next request
app.use((req, res, next) => {
  const s = req.session;
  if (s && s.user && (s.user.accessToken || s.user.refreshToken)) s.user = sealUserTokens(s.user);
  if (s && s.passport && s.passport.user && (s.passport.user.accessToken || s.passport.user.refreshToken)) {
    s.passport.user = { id: s.passport.user.id };
  }
  next();
});

app.use(passport.initialize());
app.use(passport.session());

app.use('/admin', express.static(path.join(__dirname, 'admin/public')));
// Organization portal: a simpler page for an organization's own admins (same sign-in and API as /admin)
app.use('/org', express.static(path.join(__dirname, 'org/public')));
app.get(['/org', '/org/'], (req, res) => res.sendFile(path.join(__dirname, 'org/public/index.html')));

// Serve admin SPA for any /admin/* path that isn't an API call.
// This ensures refreshing on any hash (e.g. /admin/#threats) still loads the app.
app.get('/admin', (req, res) =>
  res.sendFile(path.join(__dirname, 'admin/public/index.html'))
);
app.get('/admin/', (req, res) =>
  res.sendFile(path.join(__dirname, 'admin/public/index.html'))
);
// ── Local development: serve the frontend from this server too ──
// (In production genjutsu.org's Cloudflare Worker serves it.)
const FRONTEND_DIR = path.join(__dirname, '../frontend');
if (process.env.NODE_ENV !== 'production' && require('fs').existsSync(FRONTEND_DIR)) {
  app.use(express.static(FRONTEND_DIR));
}

app.use('/auth',      authRoutes);
// Rate limits: generous overall, tighter on scans and AI
// Health check for the Cloudflare worker's failover. Doesn't touch the database,
// so checking it never wakes the database up.
app.get('/api/health', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ ok: true, server: require('./database/db').SERVER_NAME, uptime: Math.round(process.uptime()) });
});

app.use('/api', rateLimit({ name: 'api', windowMs: 60 * 1000, max: 240 }));
app.use(['/api/emails', '/api/threats', '/api/analytics'], rateLimit({ name: 'scan', windowMs: 60 * 1000, max: 30, message: 'Scanning too often. Please wait a minute.' }));
app.use('/api/ai', rateLimit({ name: 'ai', windowMs: 60 * 1000, max: 12, message: 'Too many AI requests. Please wait a minute.' }));
app.use('/api/v1',    require('./routes/publicApi'));   // API-key access for other tools
app.use('/api',       accountRoutes);
app.use('/api',       emailRoutes);
app.use('/api',       threatRoutes);
app.use('/api',       honeypotRoutes);
app.use('/api',       settingsRoutes);
app.use('/api',       analyticsRoutes);
app.use('/api',       notificationsRoutes);
app.use('/api',       aiChatRoutes);
app.use('/admin/api/login', rateLimit({ name: 'admin-login', windowMs: 60 * 1000, max: 20, message: 'Too many sign-in attempts. Wait a minute.' }));
app.use('/admin/api', adminRoutes);

app.use((req, res) => res.status(404).json({ error: 'Not found' }));

if (!process.env.DATABASE_URL) {
  console.error('\n DATABASE_URL is empty — Genjutsu needs a PostgreSQL database.');
  console.error(' Put a connection string in backend/.env.local (free: https://neon.tech) and start again.\n');
  process.exit(1);
}

initDB().then(async () => {
  try { await encryptStoredTokens(); } catch (e) { console.warn('⚠️  Could not encrypt stored tokens:', e.message); }
  try { await require('./database/adminDb').initAdminDb(); } catch (e) { console.warn('⚠️  Admin tables:', e.message); }
  try {
    const r = await require('./services/threatRecords').reclassifyOnce(query);
    if (r) console.log(`🔁 Re-sorted saved threats: ${r.changed} of ${r.checked} got a corrected type`);
  } catch (e) { console.warn('⚠️  Re-sorting saved threats:', e.message); }
  try {
    const trainer = require('./services/modelTrainer');
    await trainer.initTrainingDb();
    await trainer.loadDataset();
    await trainer.loadActive();
    trainer.startTrainingScheduler();
    const feed = require('./services/sharedFeed');
    await feed.initSharedFeed();
    await require('./services/attachmentScanner').initAttachmentDb();
    await require('./services/orgs').initOrgs();
    feed.startSharedFeed();
  } catch (e) { console.warn('⚠️  Model training setup:', e.message); }
  startDigestScheduler();
  try {
    const n = await require('./database/db').recountHoneypotEffort();
    if (n) console.log(`🍯 Recounted scammer effort for ${n} honeypot conversation(s)`);
  } catch (e) { console.warn('⚠️  Honeypot recount:', e.message); }
  require('./services/honeypotRunner').startHoneypotRunner();
  const { pruneDemoUsers } = require('./database/db');
  setInterval(() => pruneDemoUsers().catch(() => {}), 60 * 60 * 1000).unref();
  app.listen(PORT, () => {
    console.log(`\n Genjutsu v3 running on port ${PORT}`);
    if (process.env.NODE_ENV !== 'production') console.log(`   Open    → http://localhost:${PORT}`);
    console.log(`   DB → PostgreSQL (persistent)`);
    console.log(`   Admin → ${process.env.ADMIN_EMAIL || 'not set'}\n`);
  });
}).catch(err => {
  console.error('Failed to connect to PostgreSQL:', err.message);
  process.exit(1);
});
