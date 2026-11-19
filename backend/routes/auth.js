// ============================================================
// routes/auth.js — Login (Google, Microsoft, IMAP) / Logout / Session
// ============================================================
const express  = require('express');
const passport = require('../config/passport');
const { sealUserTokens } = require('../services/mail/tokens');
const router   = express.Router();
const crypto   = require('crypto');
const { upsertUser, getUserByEmail } = require('../database/db');
const mail     = require('../services/mail');
const outlook  = require('../services/mail/outlookProvider');
const imap     = require('../services/mail/imapProvider');
const { seal } = require('../services/mail/secretBox');

const FRONTEND = () => process.env.FRONTEND_URL || 'https://genjutsu.org';
const PROVIDER_NAMES = { google: 'Google (Gmail)', microsoft: 'Microsoft (Outlook)', imap: 'Other email (IMAP)' };

// Save a non-Google user and start a fresh session (prevents session fixation).
// Returns { ok } | { conflict: provider } | { suspended: true }
async function startSession(req, user) {
  const existing = await getUserByEmail(user.email);
  if (existing && existing.user_id !== user.id) return { conflict: existing.provider || 'google' };
  await upsertUser(user);
  await require('../services/orgs').joinByDomain(user).catch(() => null);   // organization staff join their organization automatically
  if (existing && existing.status === 'suspended') return { suspended: true };
  await new Promise((resolve, reject) => req.session.regenerate(e => e ? reject(e) : resolve()));
  req.session.user = sealUserTokens(user);   // tokens stored encrypted
  require('../database/db').logUserActivity(user.id, 'Signed in', user.provider || 'google');
  await new Promise((resolve, reject) => req.session.save(e => e ? reject(e) : resolve()));
  return { ok: true };
}

// Simple in-memory limiter for the IMAP password form (5 tries / 15 min / IP)
const imapAttempts = new Map();
function imapRateLimited(ip) {
  const now = Date.now();
  const recent = (imapAttempts.get(ip) || []).filter(t => now - t < 15 * 60 * 1000);
  recent.push(now);
  imapAttempts.set(ip, recent);
  return recent.length > 5;
}

router.get('/google',
  passport.authenticate('google', {
    scope: ['profile','email',
      'https://www.googleapis.com/auth/gmail.readonly',
      'https://www.googleapis.com/auth/gmail.send',
      'https://www.googleapis.com/auth/gmail.modify'],
    accessType: 'offline', prompt: 'consent'
  })
);

router.get('/google/callback', (req, res, next) => {
  passport.authenticate('google', (err, user, info) => {
    if (err) return next(err);
    if (!user) {
      return res.redirect(info && info.reason === 'conflict'
        ? `/auth/conflict?provider=${encodeURIComponent(info.existingProvider)}`
        : '/auth/suspended');
    }
    req.logIn(user, (loginErr) => {
      if (loginErr) return next(loginErr);
      req.session.user = sealUserTokens(user);   // tokens stored encrypted
      require('../database/db').logUserActivity(user.id, 'Signed in', 'google');
      res.redirect(FRONTEND());
    });
  })(req, res, next);
});

// ── Microsoft (Outlook.com, Hotmail, Live, Microsoft 365) ─────
router.get('/microsoft', (req, res) => {
  if (!outlook.isConfigured()) {
    return res.status(503).send('Microsoft sign-in is not set up on this server yet (MICROSOFT_CLIENT_ID / MICROSOFT_CLIENT_SECRET / MICROSOFT_CALLBACK_URL).');
  }
  const state = crypto.randomBytes(16).toString('hex');
  req.session.msOAuthState = state;          // CSRF protection for the OAuth round trip
  req.session.save(() => res.redirect(outlook.authUrl(state)));
});

router.get('/microsoft/callback', async (req, res) => {
  try {
    if (req.query.error) return res.redirect('/auth/failed?provider=microsoft');
    const expected = req.session.msOAuthState;
    if (!expected || req.query.state !== expected) {
      return res.status(400).send('Sign-in expired or was tampered with. Please try again.');
    }
    delete req.session.msOAuthState;

    const tokens  = await outlook.exchangeCode(req.query.code);
    const profile = await outlook.getProfile(tokens.access_token);
    const email   = profile.mail || profile.userPrincipalName;
    if (!email) return res.redirect('/auth/failed?provider=microsoft');

    const result = await startSession(req, {
      id:           `ms-${profile.id}`,
      name:         profile.displayName || email.split('@')[0],
      email,
      picture:      '',
      accessToken:  tokens.access_token,
      refreshToken: tokens.refresh_token || null,
      provider:     'microsoft'
    });
    if (result.conflict)  return res.redirect(`/auth/conflict?provider=${encodeURIComponent(result.conflict)}`);
    if (result.suspended) return res.redirect('/auth/suspended');
    res.redirect(FRONTEND());
  } catch (err) {
    console.error('[Auth] Microsoft sign-in failed:', err.message);
    res.redirect('/auth/failed?provider=microsoft');
  }
});

// ── Other mailboxes over IMAP (Yahoo, iCloud, AOL, Zoho, GMX, Yandex, custom) ──
router.get('/imap/providers', (req, res) => res.json({ success: true, providers: imap.publicPresets() }));

router.post('/imap', async (req, res) => {
  if (imapRateLimited(req.ip)) {
    return res.status(429).json({ success: false, error: 'Too many attempts. Please wait 15 minutes and try again.' });
  }
  let creds;
  try {
    creds = imap.buildCredentials(req.body || {});
  } catch (err) {
    return res.status(400).json({ success: false, error: err.message });
  }
  try {
    await imap.verify(creds);
  } catch (err) {
    console.warn('[Auth] IMAP sign-in failed for', creds.email, '-', err.message);
    return res.status(401).json({
      success: false,
      error: 'Could not sign in to your mailbox. Check the address and use an app password (not your normal password).'
    });
  }
  try {
    // ID includes the server so a mailbox can't be confused with another server's account
    const idHash = crypto.createHash('sha256').update(`${creds.email.toLowerCase()}|${creds.imap.host.toLowerCase()}`).digest('hex').slice(0, 24);
    const result = await startSession(req, {
      id:           `imap-${idHash}`,
      name:         creds.email.split('@')[0],
      email:        creds.email,
      picture:      '',
      accessToken:  null,
      refreshToken: null,
      provider:     'imap',
      mailProvider: creds.provider,
      mailCreds:    seal(creds)
    });
    if (result.conflict) {
      return res.status(409).json({ success: false, error: `This address already uses ${PROVIDER_NAMES[result.conflict] || result.conflict} sign-in on Genjutsu. Please use that option.` });
    }
    if (result.suspended) return res.status(403).json({ success: false, suspended: true, error: 'Your account has been suspended. Contact the administrator.' });
    imapAttempts.delete(req.ip);
    res.json({ success: true, sid: req.sessionID });
  } catch (err) {
    console.error('[Auth] IMAP session error:', err.message);
    res.status(500).json({ success: false, error: 'Sign-in failed. Please try again.' });
  }
});

router.get('/conflict', (req, res) => {
  const name = PROVIDER_NAMES[req.query.provider] || 'another sign-in option';
  res.status(409).send(`<!DOCTYPE html><html><head><title>Use your existing sign-in — Genjutsu</title>
    <style>body{font-family:sans-serif;background:#0f172a;color:#f8fafc;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
    .box{text-align:center;padding:40px;background:#1e293b;border-radius:12px;max-width:420px}h2{color:#f59e0b}p{color:#94a3b8}a{color:#818cf8}</style></head>
    <body><div class="box"><h2>Already registered</h2>
    <p>This email address already uses <b>${name}</b> to sign in to Genjutsu.</p>
    <p>Please go back and choose that option.</p><p><a href="${FRONTEND()}">Back to Genjutsu</a></p></div></body></html>`);
});

router.get('/suspended', (req, res) =>
  res.status(403).send(`
    <!DOCTYPE html>
    <html>
    <head><title>Account Suspended — Genjutsu</title>
    <style>
      body { font-family: sans-serif; background: #0f172a; color: #f8fafc;
             display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
      .box { text-align: center; padding: 40px; background: #1e293b; border-radius: 12px; max-width: 400px; }
      h2 { color: #ef4444; } p { color: #94a3b8; }
      a { color: #818cf8; }
    </style></head>
    <body>
      <div class="box">
        <h2>🚫 Account Suspended</h2>
        <p>Your account has been suspended by the administrator.</p>
        <p>Contact <a href="mailto:princemagar338@gmail.com">princemagar338@gmail.com</a> for support.</p>
      </div>
    </body>
    </html>
  `)
);

router.get('/failed', (req, res) =>
  res.status(401).json({ success: false, message: `${req.query.provider === 'microsoft' ? 'Microsoft' : 'Google'} login failed.` })
);

// ── Demo mode: a sample mailbox, no sign-in, nothing sent ─────
router.post('/demo', async (req, res) => {
  try {
    const id = `demo-${crypto.randomBytes(8).toString('hex')}`;
    const result = await startSession(req, { id, name: 'Demo user', email: `${id}@demo.genjutsu`, picture: '', provider: 'demo', accessToken: null, refreshToken: null });
    if (!result.ok) return res.status(500).json({ success: false, error: 'Could not start the demo' });
    res.json({ success: true, sessionId: req.sessionID });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/me', (req, res) => {
  if (req.session.user) {
    const { name, email, picture } = req.session.user;
    const provider = req.session.user.provider || 'google';
    return res.json({ loggedIn: true, user: { name, email, picture, provider, providerLabel: mail.providerLabel(req.session.user), demo: provider === 'demo' } });
  }
  res.json({ loggedIn: false, user: null });
});

router.get('/logout', (req, res) =>
  req.session.destroy(() => res.json({ success: true }))
);

module.exports = router;
