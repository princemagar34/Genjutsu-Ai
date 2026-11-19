// ============================================================
// services/mail/tokens.js — keep OAuth tokens encrypted at rest
// ------------------------------------------------------------
// Google / Microsoft access and refresh tokens give full access to a
// mailbox, so they are never stored in plain text — not in the users
// table and not in the login session (which also lives in Postgres).
//
//   session user:  { id, email, …, tokenBox: 'v1:…' }   ← sealed
//   during a call: { …, accessToken, refreshToken }      ← in memory only
//
// Sealing uses secretBox (AES-256-GCM), the same as IMAP app passwords.
// ============================================================
const { seal, open } = require('./secretBox');

const isSealed = v => typeof v === 'string' && v.startsWith('v1:');

// Copy of a user that is safe to store: plain tokens replaced by tokenBox
function sealUserTokens(user) {
  if (!user) return user;
  const { accessToken, refreshToken, ...rest } = user;
  if (accessToken || refreshToken) {
    rest.tokenBox = seal({ a: accessToken || null, r: refreshToken || null });
  }
  return rest;
}

// In-memory copy with tokens opened, for talking to Gmail / Outlook
function withTokens(user) {
  if (!user) return user;
  const ctx = { ...user };
  delete ctx.tokenBox;
  if (user.tokenBox) {
    const t = open(user.tokenBox);
    ctx.accessToken = t.a;
    ctx.refreshToken = t.r;
  }
  // Sessions created before encryption still hold plain tokens: use them once
  return ctx;
}

// After a call: if the provider refreshed a token, store the new one sealed,
// and make sure no plain token is left on the stored session user.
function persistTokens(user, ctx) {
  if (!user || !ctx) return;
  const before = user.tokenBox ? open(user.tokenBox) : { a: user.accessToken || null, r: user.refreshToken || null };
  const after  = { a: ctx.accessToken || null, r: ctx.refreshToken || null };
  const plainLeft = 'accessToken' in user || 'refreshToken' in user;
  if (plainLeft || before.a !== after.a || before.r !== after.r) {
    delete user.accessToken;
    delete user.refreshToken;
    if (after.a || after.r) user.tokenBox = seal(after); else delete user.tokenBox;
  }
}

// For the users table: one column value, sealed (null stays null)
const sealColumn = v => (v == null || v === '' ? null : (isSealed(v) ? v : seal(v)));

module.exports = { sealUserTokens, withTokens, persistTokens, sealColumn, isSealed };
