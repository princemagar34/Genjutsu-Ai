// ============================================================
// server.js — Genjutsu Main Entry Point (Cloudflare-ready)
// ============================================================
require('dotenv').config();

const express      = require('express');
const session      = require('express-session');
const cors         = require('cors');
const passport     = require('./config/passport');
const path         = require('path');
const SQLiteStore  = require('connect-sqlite3')(session); // FIX: persistent session store

const authRoutes          = require('./routes/auth');
const emailRoutes         = require('./routes/emails');
const threatRoutes        = require('./routes/threats');
const honeypotRoutes      = require('./routes/honeypot');
const settingsRoutes      = require('./routes/settings');
const analyticsRoutes     = require('./routes/analytics');
const notificationsRoutes = require('./routes/notifications');  // ← NEW
const aiChatRoutes        = require('./routes/aichat');         // ← NEW
const adminRoutes         = require('./admin/adminRoutes');

const app  = express();
const PORT = process.env.PORT || 3001;

// ── Trust Cloudflare proxy ────────────────────────────────────
app.set('trust proxy', 1);

// ── CORS ──────────────────────────────────────────────────────
const ALLOWED_ORIGINS = [
  'https://genjutsu.org',
  'https://www.genjutsu.org',
  'https://genjutsu.princemagar338.workers.dev',
  'http://localhost:3001',
  'http://localhost:5500'
];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS blocked: ${origin}`));
    }
  },
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Session ───────────────────────────────────────────────────
app.use(session({
  secret:            process.env.SESSION_SECRET || 'genjutsu_dev_secret_change_this',
  resave:            false,
  saveUninitialized: false,
  // FIX: persist sessions to SQLite so users stay logged in after server restarts
  store: new SQLiteStore({ db: 'sessions.db', dir: './database' }),
  cookie: {
    secure:   process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge:   24 * 60 * 60 * 1000
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// ── Static files ──────────────────────────────────────────────
// Frontend is served by Cloudflare Workers — not here
app.use('/admin', express.static(path.join(__dirname, 'admin/public')));

// ── Routes ────────────────────────────────────────────────────
app.use('/auth',      authRoutes);
app.use('/api',       emailRoutes);
app.use('/api',       threatRoutes);
app.use('/api',       honeypotRoutes);
app.use('/api',       settingsRoutes);
app.use('/api',       analyticsRoutes);
app.use('/api',       notificationsRoutes);  // ← NEW
app.use('/api',       aiChatRoutes);         // ← NEW
app.use('/admin/api', adminRoutes);

// ── Admin panel ───────────────────────────────────────────────
app.get('/admin', (req, res) =>
  res.sendFile(path.join(__dirname, 'admin/public/index.html'))
);

// ── 404 fallback ──────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// ── Start ─────────────────────────────────────────────────────
app.listen(PORT, () => {
  const tg  = process.env.TELEGRAM_BOT_TOKEN  ? '✅ Connected'            : '❌ Not set';
  const ai  = process.env.GROQ_API_KEY   ? '✅ Connected'            : '❌ Not set (AI chat disabled)';
  const adm = process.env.ADMIN_EMAIL         ? `✅ ${process.env.ADMIN_EMAIL}` : '❌ Not set';
  console.log(`\n🛡️  Genjutsu v3 running!`);
  console.log(`   App      →  http://localhost:${PORT}`);
  console.log(`   Login    →  http://localhost:${PORT}/auth/google`);
  console.log(`   Admin    →  http://localhost:${PORT}/admin`);
  console.log(`   Telegram → ${tg}`);
  console.log(`   AI Chat  → ${ai}`);
  console.log(`   Admin    → ${adm}\n`);
});
