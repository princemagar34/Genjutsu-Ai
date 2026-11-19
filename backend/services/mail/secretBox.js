// ============================================================
// services/mail/secretBox.js — encrypt mailbox credentials at rest
// ------------------------------------------------------------
// IMAP/SMTP mailboxes (Yahoo, iCloud, Zoho …) need an app password.
// It is never stored in plain text: it is sealed with AES-256-GCM
// before it goes into the session store or the users table.
// Key: MAIL_ENCRYPTION_KEY (falls back to SESSION_SECRET).
// ============================================================
const crypto = require('crypto');

function getKey() {
  const secret = process.env.MAIL_ENCRYPTION_KEY || process.env.SESSION_SECRET;
  if (!secret) {
    throw new Error('MAIL_ENCRYPTION_KEY (or SESSION_SECRET) must be set to store mailbox credentials');
  }
  return crypto.createHash('sha256').update(String(secret)).digest();
}

function seal(value) {
  const iv      = crypto.randomBytes(12);
  const cipher  = crypto.createCipheriv('aes-256-gcm', getKey(), iv);
  const payload = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  const tag     = cipher.getAuthTag();
  return 'v1:' + Buffer.concat([iv, tag, payload]).toString('base64');
}

function open(sealed) {
  if (!sealed || !String(sealed).startsWith('v1:')) throw new Error('No stored mailbox credentials — please sign in again');
  const raw      = Buffer.from(String(sealed).slice(3), 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', getKey(), raw.subarray(0, 12));
  decipher.setAuthTag(raw.subarray(12, 28));
  const text = Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString('utf8');
  return JSON.parse(text);
}

module.exports = { seal, open };
