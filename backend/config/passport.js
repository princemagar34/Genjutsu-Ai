// ============================================================
// config/passport.js — Google OAuth 2.0 + DB save on login
// ============================================================
const passport       = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { upsertUser } = require('../database/db');

passport.use(new GoogleStrategy({
    clientID:     process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL:  process.env.GOOGLE_CALLBACK_URL
  },
  (accessToken, refreshToken, profile, done) => {
    const user = {
      id:           profile.id,
      name:         profile.displayName,
      email:        profile.emails[0].value,
      picture:      profile.photos[0]?.value || '',
      accessToken,
      refreshToken
    };
    upsertUser(user); // ← saves/updates user in SQLite
    return done(null, user);
  }
));

passport.serializeUser((user, done)   => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

module.exports = passport;
