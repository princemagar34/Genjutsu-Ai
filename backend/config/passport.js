// ============================================================
// config/passport.js — Google OAuth 2.0 + DB save on login
// ============================================================
const passport       = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { upsertUser, getUserByEmail } = require('../database/db');

passport.use(new GoogleStrategy({
    clientID:     process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL:  process.env.GOOGLE_CALLBACK_URL
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      const user = {
        id:           profile.id,
        name:         profile.displayName,
        email:        profile.emails[0].value,
        picture:      profile.photos[0]?.value || '',
        accessToken,
        refreshToken
      };

      await upsertUser(user);

      // ── Suspension check ──────────────────────────────────
      // Block suspended users from logging in
      const dbUser = await getUserByEmail(user.email);
      if (dbUser && dbUser.status === 'suspended') {
        return done(null, false, { message: 'Your account has been suspended. Contact the administrator.' });
      }

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

passport.serializeUser((user, done)   => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

module.exports = passport;
