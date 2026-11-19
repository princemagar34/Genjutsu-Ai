// services/attachmentScanner.js — runs the file inspector on each email's attachments
// before the email is scored.
// • downloads at most 4 files per email and 25 per scan, each up to 10 MB
// • the bytes stay in memory and are thrown away; only the result (and the file's SHA-256
//   fingerprint) is saved, so the same file is never downloaded twice
// • links found inside files (QR codes, PDF links, Office external links) are added to the
//   email's links, so the normal link checks (look-alikes, new domains, Safe Browsing,
//   block list, shared feed) run on them too
const { inspect } = require('./fileInspector');
const db = () => require('../database/db');

const MAX_BYTES = 10 * 1024 * 1024, PER_EMAIL = 4, PER_SCAN = 25;
const WORTH = /\.(pdf|docx?|docm|dotm|xlsx?|xlsm|xlsb|pptx?|pptm|rtf|zip|rar|7z|html?|svg|png|jpe?g|exe|scr|js|vbs|iso|img|lnk|hta)$/i;

async function initAttachmentDb() {
  await db().query(`
    CREATE TABLE IF NOT EXISTS attachment_scans (
      cache_key  TEXT PRIMARY KEY,
      sha256     TEXT,
      filename   TEXT,
      result     TEXT NOT NULL,
      scanned_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS attachment_scans_sha ON attachment_scans (sha256);`);
}

const keyOf = (user, email, att) => `${user.provider || 'google'}:${user.id}:${email.id}:${att.attachmentId || att.filename}:${att.size || 0}`;

async function prepare(user, emails, { getAttachment = (u, e, a) => require('./mail').getAttachment(u, e, a) } = {}) {
  if (!user || !Array.isArray(emails) || !emails.length) return { downloaded: 0 };
  const jobs = [];
  for (const email of emails) {
    const atts = (email.attachments || []).filter(a => (a.size || 0) <= MAX_BYTES && (WORTH.test(a.filename || '') || /^image\/(png|jpe?g)|pdf|zip|officedocument|msword|ms-excel|html|svg/i.test(a.mimeType || '')));
    for (const att of atts.slice(0, PER_EMAIL)) jobs.push({ email, att, key: keyOf(user, email, att) });
  }
  if (!jobs.length) return { downloaded: 0 };
  let cached = new Map();
  try {
    const { rows } = await db().query('SELECT cache_key, result FROM attachment_scans WHERE cache_key = ANY($1)', [jobs.map(j => j.key)]);
    cached = new Map(rows.map(r => [r.cache_key, JSON.parse(r.result)]));
  } catch (_) { /* no cache: still scan */ }

  let downloaded = 0;
  for (const j of jobs) {
    let result = cached.get(j.key);
    if (!result) {
      if (downloaded >= PER_SCAN) continue;
      let buf = null;
      try { buf = await getAttachment(user, j.email, j.att); } catch (e) { continue; }
      if (!buf || !buf.length || buf.length > MAX_BYTES) continue;
      downloaded++;
      const r = inspect(buf, j.att.filename, j.att.mimeType);
      result = { kind: r.kind, sha256: r.sha256, findings: r.findings, urls: r.urls, qr: r.qr };
      try { await db().query(`INSERT INTO attachment_scans (cache_key, sha256, filename, result) VALUES ($1,$2,$3,$4) ON CONFLICT (cache_key) DO NOTHING`,
        [j.key, r.sha256, String(j.att.filename || '').slice(0, 300), JSON.stringify(result)]); } catch (_) {}
    }
    attach(j.email, j.att.filename, result);
  }
  return { downloaded };
}

// Put a file's result onto the email (used by prepare, and by tests)
function attach(email, filename, result) {
  email.fileFindings = email.fileFindings || [];
  email.fileFindings.push({ filename, ...result });
  if (result.urls?.length) {
    email.links = [...new Set([...(email.links || []), ...result.urls])];
    email.fileLinks = [...new Set([...(email.fileLinks || []), ...result.urls])];
  }
}

module.exports = { initAttachmentDb, prepare, attach, MAX_BYTES, PER_EMAIL, PER_SCAN };
