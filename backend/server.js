// ============================================================
// server.js — Genjutsu Main Entry Point (Cloudflare-ready)
// ============================================================
require('dotenv').config();

const express      = require('express');
const session      = require('express-session');
const cors         = require('cors');
const passport     = require('./config/passport');
const path         = require('path');
const pgSession    = require('connect-pg-simple')(session);
const { pool, initDB } = require('./database/db');

const authRoutes          = require('./routes/auth');
const emailRoutes         = require('./routes/emails');
const threatRoutes        = require('./routes/threats');
const honeypotRoutes      = require('./routes/honeypot');
const settingsRoutes      = require('./routes/settings');
const analyticsRoutes     = require('./routes/analytics');
const notificationsRoutes = require('./routes/notifications');
const aiChatRoutes        = require('./routes/aichat');
const adminRoutes         = require('./admin/adminRoutes');

const app  = express();
const PORT = process.env.PORT || 3001;

app.set('trust proxy', 1);

const ALLOWED_ORIGINS = [
  'https://genjutsu.org',
  'https://www.genjutsu.org',
  'https://genjutsu.princemagar338.workers.dev',
  'http://localhost:3001',
  'http://localhost:5500'
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
    pool,
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

app.use(passport.initialize());
app.use(passport.session());

app.use('/admin', express.static(path.join(__dirname, 'admin/public')));

// Serve admin SPA for any /admin/* path that isn't an API call.
// This ensures refreshing on any hash (e.g. /admin/#threats) still loads the app.
app.get('/admin', (req, res) =>
  res.sendFile(path.join(__dirname, 'admin/public/index.html'))
);
app.get('/admin/', (req, res) =>
  res.sendFile(path.join(__dirname, 'admin/public/index.html'))
);
app.use('/auth',      authRoutes);
app.use('/api',       emailRoutes);
app.use('/api',       threatRoutes);
app.use('/api',       honeypotRoutes);
app.use('/api',       settingsRoutes);
app.use('/api',       analyticsRoutes);
app.use('/api',       notificationsRoutes);
app.use('/api',       aiChatRoutes);
app.use('/admin/api', adminRoutes);

app.use((req, res) => res.status(404).json({ error: 'Not found' }));

initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`\n Genjutsu v3 running on port ${PORT}`);
    console.log(`   DB → PostgreSQL (persistent)`);
    console.log(`   Admin → ${process.env.ADMIN_EMAIL || 'not set'}\n`);
  });
}).catch(err => {
  console.error('Failed to connect to PostgreSQL:', err.message);
  process.exit(1);
});
