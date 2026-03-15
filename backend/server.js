// ============================================================
// server.js — Genjutsu Main Entry Point (Cloudflare-ready)
// ============================================================
require('dotenv').config();

const express  = require('express');
const session  = require('express-session');
const cors     = require('cors');
const passport = require('./config/passport');
const path     = require('path');

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
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Session ───────────────────────────────────────────────────
app.use(session({
  secret:            process.env.SESSION_SECRET || 'genjutsu_dev_secret_change_this',
  resave:            false,
  saveUninitialized: false,
  cookie: {
    secure:   process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge:   24 * 60 * 60 * 1000
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// ── Static files ──────────────────────────────────────────────
app.use(express.static(path.join(__dirname, '../frontend')));
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

// ── SPA fallback ──────────────────────────────────────────────
app.get('*', (req, res) =>
  res.sendFile(path.join(__dirname, '../frontend/index.html'))
);

// ── Start ─────────────────────────────────────────────────────
app.listen(PORT, () => {
  const tg  = process.env.TELEGRAM_BOT_TOKEN  ? '✅ Connected'            : '❌ Not set';
  const ai  = process.env.GEMINI_API_KEY ? '✅ Connected'            : '❌ Not set (AI chat disabled)';
  const adm = process.env.ADMIN_EMAIL         ? `✅ ${process.env.ADMIN_EMAIL}` : '❌ Not set';
  console.log(`\n🛡️  Genjutsu v3 running!`);
  console.log(`   App      →  http://localhost:${PORT}`);
  console.log(`   Login    →  http://localhost:${PORT}/auth/google`);
  console.log(`   Admin    →  http://localhost:${PORT}/admin`);
  console.log(`   Telegram → ${tg}`);
  console.log(`   AI Chat  → ${ai}`);
  console.log(`   Admin    → ${adm}\n`);
});
