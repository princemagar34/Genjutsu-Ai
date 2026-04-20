// ============================================================
// routes/auth.js — Google OAuth Login / Logout / Session
// ============================================================
const express  = require('express');
const passport = require('../config/passport');
const router   = express.Router();

router.get('/google',
  passport.authenticate('google', {
    scope: ['profile','email',
      'https://www.googleapis.com/auth/gmail.readonly',
      'https://www.googleapis.com/auth/gmail.send',
      'https://www.googleapis.com/auth/gmail.modify'],
    accessType: 'offline', prompt: 'consent'
  })
);

router.get('/google/callback',
  passport.authenticate('google', { failureRedirect: '/auth/suspended' }),
  (req, res) => { req.session.user = req.user; res.redirect(process.env.FRONTEND_URL || 'https://genjutsu.org'); }
);

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
  res.status(401).json({ success: false, message: 'Google login failed.' })
);

router.get('/me', (req, res) => {
  if (req.session.user) {
    const { name, email, picture } = req.session.user;
    return res.json({ loggedIn: true, user: { name, email, picture } });
  }
  res.json({ loggedIn: false, user: null });
});

router.get('/logout', (req, res) =>
  req.session.destroy(() => res.json({ success: true }))
);

module.exports = router;
