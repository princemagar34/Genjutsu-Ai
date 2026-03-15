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
  passport.authenticate('google', { failureRedirect: '/auth/failed' }),
  (req, res) => { req.session.user = req.user; res.redirect('/'); }
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
