// admin/adminAuth.js — admin sign-in security
// Passwords: scrypt hashes ("scrypt$<salt>$<hash>"), never stored readable.
// 2-step login: standard 6-digit codes (TOTP, RFC 6238) for Google Authenticator etc.
// Login limit: 5 wrong tries per email (and per IP) → locked for 15 minutes.
const crypto = require('crypto');

// ── Passwords ────────────────────────────────────────────────
const MIN_PASSWORD = 10;
function passwordProblem(pw) {
  pw = String(pw || '');
  if (pw.length < MIN_PASSWORD) return `Password must be at least ${MIN_PASSWORD} characters.`;
  if (!/[A-Za-z]/.test(pw) || !/[0-9]/.test(pw)) return 'Use both letters and numbers.';
  if (/^(.)\1+$/.test(pw)) return 'That password is too simple.';
  return null;
}
function isHashed(stored) { return typeof stored === 'string' && stored.startsWith('scrypt$'); }
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(pw), salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt.toString('base64')}$${hash.toString('base64')}`;
}
function verifyPassword(pw, stored) {
  if (!stored) return false;
  if (!isHashed(stored)) {           // old plain-text row: compare in constant time, caller then upgrades it
    const a = Buffer.from(String(pw)), b = Buffer.from(String(stored));
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }
  const [, saltB64, hashB64] = stored.split('$');
  const want = Buffer.from(hashB64, 'base64');
  const got = crypto.scryptSync(String(pw), Buffer.from(saltB64, 'base64'), want.length, { N: 16384, r: 8, p: 1 });
  return crypto.timingSafeEqual(got, want);
}

// ── 2-step codes (TOTP) ──────────────────────────────────────
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const byte of buf) { value = (value << 8) | byte; bits += 8; while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0, value = 0; const out = [];
  for (const ch of clean) { value = (value << 5) | B32.indexOf(ch); bits += 5; if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; } }
  return Buffer.from(out);
}
function newTotpSecret() { return base32Encode(crypto.randomBytes(20)); }
function totpAt(secret, counter) {
  const buf = Buffer.alloc(8); buf.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', base32Decode(secret)).update(buf).digest();
  const o = h[h.length - 1] & 15;
  const n = ((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1e6).padStart(6, '0');
}
// Accepts the code for now, 30 s before or 30 s after (phone clocks drift). Returns the step used, or -1.
function verifyTotp(secret, code, now = Date.now()) {
  code = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(code) || !secret) return -1;
  const step = Math.floor(now / 30000);
  for (const d of [0, -1, 1]) {
    const c = Buffer.from(totpAt(secret, step + d));
    if (crypto.timingSafeEqual(c, Buffer.from(code))) return step + d;
  }
  return -1;
}
function otpauthUrl(secret, email) {
  return `otpauth://totp/${encodeURIComponent('Genjutsu Admin:' + email)}?secret=${secret}&issuer=${encodeURIComponent('Genjutsu Admin')}&algorithm=SHA1&digits=6&period=30`;
}
function recoveryCodes(n = 8) {
  return Array.from({ length: n }, () => crypto.randomBytes(5).toString('hex').replace(/(.{5})/, '$1-'));
}
const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

// ── Login limit ──────────────────────────────────────────────
const MAX_FAILS = 5, LOCK_MS = 15 * 60 * 1000;
const fails = new Map();   // key -> { n, until, first }
function lockedFor(keys, now = Date.now()) {
  let wait = 0;
  for (const k of keys) { const f = fails.get(k); if (f && f.until > now) wait = Math.max(wait, f.until - now); }
  return wait;
}
function recordFail(keys, now = Date.now()) {
  for (const k of keys) {
    const f = fails.get(k);
    const cur = (!f || now - f.first > LOCK_MS) ? { n: 0, until: 0, first: now } : f;
    cur.n += 1;
    if (cur.n >= MAX_FAILS) cur.until = now + LOCK_MS;
    fails.set(k, cur);
  }
}
function clearFails(keys) { for (const k of keys) fails.delete(k); }
function triesLeft(keys) { return Math.max(0, MAX_FAILS - Math.max(0, ...keys.map(k => fails.get(k)?.n || 0))); }

// A short label for "the device", used to spot logins from somewhere new.
function deviceLabel(ua = '') {
  const b = /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) ? 'Chrome' : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const o = /Windows/.test(ua) ? 'Windows' : /Mac OS X|Macintosh/.test(ua) ? 'Mac' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iPhone' : /Linux/.test(ua) ? 'Linux' : 'unknown system';
  return `${b} on ${o}`;
}

module.exports = {
  MIN_PASSWORD, passwordProblem, isHashed, hashPassword, verifyPassword,
  newTotpSecret, verifyTotp, totpAt, otpauthUrl, recoveryCodes, sha256, base32Decode,
  MAX_FAILS, LOCK_MS, lockedFor, recordFail, clearFails, triesLeft, _fails: fails, deviceLabel,
};
