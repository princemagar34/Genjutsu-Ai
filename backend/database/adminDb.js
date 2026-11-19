// database/adminDb.js — data for the admin portal
const { query } = require('./db');

// Sender domain from "Name <a@b.com>" in SQL
const DOMAIN = (col) => `lower(split_part(substring(${col} from '[^<@[:space:]]+@[^>[:space:]]+'), '@', 2))`;
const LEVEL = `COALESCE(ov.new_level, sr.threat_type)`;
// Demo accounts (sample emails) never count in admin numbers
// For a school admin this also limits everything to that school (admin/orgScope.js)
const { realUser, currentOrg } = require('../admin/orgScope');
const LATEST = `
  LEFT JOIN LATERAL (SELECT threat_type, details, mitre, origin_country, origin_ip, confidence_level
                     FROM scan_results WHERE email_id = e.email_id ORDER BY scan_timestamp DESC LIMIT 1) sr ON TRUE
  LEFT JOIN LATERAL (SELECT new_level FROM threat_overrides WHERE email_id = e.email_id ORDER BY overridden_at DESC LIMIT 1) ov ON TRUE`;

async function initAdminDb() {
  await query(`
    ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS totp_secret     TEXT;     -- sealed
    ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS totp_enabled    INTEGER DEFAULT 0;
    ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS totp_last_step  BIGINT DEFAULT 0;
    ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS recovery_codes  TEXT;     -- JSON list of sha256 hashes
    ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ;

    CREATE TABLE IF NOT EXISTS admin_devices (
      admin_email TEXT NOT NULL,
      device_hash TEXT NOT NULL,
      label       TEXT,
      ip          TEXT,
      first_seen  TIMESTAMPTZ DEFAULT NOW(),
      last_seen   TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (admin_email, device_hash)
    );
    CREATE TABLE IF NOT EXISTS announcements (
      announcement_id TEXT PRIMARY KEY,
      message    TEXT NOT NULL,
      level      TEXT DEFAULT 'info',
      created_by TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      expires_at TIMESTAMPTZ,
      active     INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS pending_actions (
      action_id    TEXT PRIMARY KEY,
      action       TEXT NOT NULL,
      payload      TEXT,
      summary      TEXT,
      requested_by TEXT NOT NULL,
      requested_at TIMESTAMPTZ DEFAULT NOW(),
      status       TEXT DEFAULT 'pending',
      decided_by   TEXT,
      decided_at   TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS admin_queue_done (
      item_key   TEXT PRIMARY KEY,
      done_by    TEXT,
      done_at    TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await hashPlainAdminPasswords();
}

// Old rows stored passwords as plain text: hash them in place, once.
async function hashPlainAdminPasswords() {
  const { hashPassword, isHashed } = require('../admin/adminAuth');
  const { rows } = await query('SELECT admin_id, password FROM admin_users');
  let n = 0;
  for (const r of rows) {
    if (r.password && !isHashed(r.password)) {
      await query('UPDATE admin_users SET password=$2 WHERE admin_id=$1', [r.admin_id, hashPassword(r.password)]);
      n++;
    }
  }
  if (n) console.log(`🔐 Hashed ${n} admin password(s) that were stored as plain text`);
  return n;
}

// ── Admin accounts ───────────────────────────────────────────
const getAdminFull = async (email) => (await query(`SELECT a.*, o.name AS org_name, o.status AS org_status FROM admin_users a
  LEFT JOIN organisations o ON o.org_id = a.org_id WHERE lower(a.email)=lower($1)`, [email])).rows[0] || null;
const getAdminById = async (id) => (await query(`SELECT a.*, o.name AS org_name, o.status AS org_status FROM admin_users a
  LEFT JOIN organisations o ON o.org_id = a.org_id WHERE a.admin_id=$1`, [id])).rows[0] || null;
const setAdminPassword = (id, hash) => query('UPDATE admin_users SET password=$2, password_changed_at=NOW() WHERE admin_id=$1', [id, hash]);
const setAdminTotp = (id, { secret, enabled, recovery }) =>
  query('UPDATE admin_users SET totp_secret=$2, totp_enabled=$3, recovery_codes=$4, totp_last_step=0 WHERE admin_id=$1',
    [id, secret, enabled ? 1 : 0, recovery ? JSON.stringify(recovery) : null]);
const setTotpStep = (id, step) => query('UPDATE admin_users SET totp_last_step=$2 WHERE admin_id=$1', [id, step]);
const setRecoveryCodes = (id, list) => query('UPDATE admin_users SET recovery_codes=$2 WHERE admin_id=$1', [id, JSON.stringify(list)]);

// Returns true when this device was never seen for this admin
async function seenDevice(email, hash, label, ip) {
  const r = await query(`INSERT INTO admin_devices (admin_email, device_hash, label, ip) VALUES ($1,$2,$3,$4)
    ON CONFLICT (admin_email, device_hash) DO UPDATE SET last_seen=NOW(), ip=EXCLUDED.ip
    RETURNING (xmax = 0) AS inserted`, [email, hash, label, ip]);
  const first = (await query('SELECT COUNT(*)::int AS n FROM admin_devices WHERE admin_email=$1', [email])).rows[0].n;
  return !!r.rows[0]?.inserted && first > 1;   // the very first device isn't "new"
}
const listDevices = async (email) => (await query('SELECT * FROM admin_devices WHERE admin_email=$1 ORDER BY last_seen DESC', [email])).rows;

// ── Announcements ────────────────────────────────────────────
const listAnnouncements = async () => currentOrg()
  ? (await query('SELECT * FROM announcements WHERE org_id=$1 ORDER BY created_at DESC LIMIT 50', [currentOrg()])).rows
  : (await query('SELECT * FROM announcements ORDER BY created_at DESC LIMIT 50')).rows;
// What a user sees: messages for everyone, plus messages from their own school
const activeAnnouncements = async (userId) => (await query(`SELECT announcement_id, message, level, created_at, org_id FROM announcements
  WHERE active=1 AND (expires_at IS NULL OR expires_at > NOW())
    AND (org_id IS NULL OR org_id = (SELECT org_id FROM users WHERE user_id=$1))
  ORDER BY created_at DESC LIMIT 3`, [String(userId || '')])).rows;
async function addAnnouncement({ message, level, expiresAt, by }) {
  const id = `ann-${Date.now()}`;
  await query('INSERT INTO announcements (announcement_id, message, level, created_by, expires_at, org_id) VALUES ($1,$2,$3,$4,$5,$6)',
    [id, message, level, by, expiresAt || null, currentOrg()]);
  return id;
}
const endAnnouncement = (id) => currentOrg()
  ? query('UPDATE announcements SET active=0 WHERE announcement_id=$1 AND org_id=$2', [id, currentOrg()])
  : query('UPDATE announcements SET active=0 WHERE announcement_id=$1', [id]);

// ── Global block list ────────────────────────────────────────
const listBlocklist = async () => (await query(`
  SELECT b.*, (SELECT COUNT(*)::int FROM emails e WHERE ${DOMAIN('e.sender_email')} = b.domain AND e.scanned_at > b.added_at) AS hits_since
  FROM global_blocklist b ORDER BY added_at DESC`)).rows;
async function addBlock(domain, reason, by) {
  await query('INSERT INTO global_blocklist (domain, reason, added_by) VALUES ($1,$2,$3) ON CONFLICT (domain) DO UPDATE SET reason=EXCLUDED.reason',
    [domain, reason || '', by]);
  require('./db').clearGlobalBlockCache();
}
async function removeBlock(domain) { await query('DELETE FROM global_blocklist WHERE domain=$1', [domain]); require('./db').clearGlobalBlockCache(); }

// ── Approvals ────────────────────────────────────────────────
async function requestAction(action, payload, summary, by) {
  const id = `act-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  await query('INSERT INTO pending_actions (action_id, action, payload, summary, requested_by) VALUES ($1,$2,$3,$4,$5)',
    [id, action, JSON.stringify(payload || {}), summary, by]);
  return id;
}
const listActions = async (status = 'pending') => (await query('SELECT * FROM pending_actions WHERE status=$1 ORDER BY requested_at DESC LIMIT 50', [status])).rows;
const getAction = async (id) => (await query('SELECT * FROM pending_actions WHERE action_id=$1', [id])).rows[0] || null;
const decideAction = (id, status, by) => query('UPDATE pending_actions SET status=$2, decided_by=$3, decided_at=NOW() WHERE action_id=$1 AND status=$4', [id, status, by, 'pending']);

// ── Threat intelligence ─────────────────────────────────────
async function topAttackers(days = 7, limit = 15) {
  return (await query(`
    SELECT ${DOMAIN('e.sender_email')} AS domain,
           COUNT(DISTINCT e.user_id)::int AS users,
           COUNT(DISTINCT e.email_id)::int AS emails,
           ROUND(MAX(e.confidence_score)*100)::int AS max_score,
           MAX(e.scanned_at) AS last_seen, MIN(e.scanned_at) AS first_seen,
           MODE() WITHIN GROUP (ORDER BY sr.origin_country) AS country,
           BOOL_OR(b.domain IS NOT NULL) AS blocked
    FROM emails e ${LATEST}
    LEFT JOIN global_blocklist b ON b.domain = ${DOMAIN('e.sender_email')}
    WHERE ${realUser()} AND e.scanned_at > NOW() - ($1 || ' days')::interval AND ${LEVEL} IN ('dangerous','suspicious')
    GROUP BY 1 HAVING ${DOMAIN('e.sender_email')} <> ''
    ORDER BY users DESC, emails DESC LIMIT $2`, [String(days), limit])).rows;
}
async function attackerDetail(domain) {
  const rows = (await query(`
    SELECT e.email_id, e.user_id, u.email AS user_email, e.sender_email, e.subject, e.scanned_at,
           ROUND(e.confidence_score*100)::int AS score, ${LEVEL} AS level, sr.details, sr.mitre, sr.origin_country, sr.origin_ip,
           EXISTS (SELECT 1 FROM blocked_emails be WHERE be.email_id = e.email_id) AS quarantined
    FROM emails e ${LATEST} LEFT JOIN users u ON u.user_id = e.user_id
    WHERE ${realUser()} AND ${DOMAIN('e.sender_email')} = $1 ORDER BY e.scanned_at DESC LIMIT 200`, [domain])).rows;
  return rows;
}
async function origins(days = 7) {
  return (await query(`
    SELECT COALESCE(sr.origin_country, '??') AS country, COUNT(*)::int AS n
    FROM emails e ${LATEST}
    WHERE ${realUser()} AND e.scanned_at > NOW() - ($1 || ' days')::interval AND ${LEVEL} IN ('dangerous','suspicious')
    GROUP BY 1 ORDER BY n DESC`, [String(days)])).rows;
}
async function liveFeed(limit = 30) {
  return (await query(`
    SELECT e.email_id, e.sender_email, e.subject, e.scanned_at, u.email AS user_email,
           ROUND(e.confidence_score*100)::int AS score, ${LEVEL} AS level, sr.mitre, sr.origin_country
    FROM emails e ${LATEST} LEFT JOIN users u ON u.user_id = e.user_id
    WHERE ${realUser()} AND ${LEVEL} IN ('dangerous','suspicious') ORDER BY e.scanned_at DESC LIMIT $1`, [limit])).rows;
}
async function hourly() {
  return (await query(`
    SELECT date_trunc('hour', e.scanned_at) AS hour,
           COUNT(*) FILTER (WHERE ${LEVEL}='dangerous')::int AS dangerous,
           COUNT(*) FILTER (WHERE ${LEVEL}='suspicious')::int AS suspicious,
           COUNT(*)::int AS scanned
    FROM emails e ${LATEST} WHERE ${realUser()} AND e.scanned_at > NOW() - interval '24 hours' GROUP BY 1 ORDER BY 1`)).rows;
}
async function counts24h() {
  const r = (await query(`
    SELECT COUNT(*)::int AS scanned,
           COUNT(*) FILTER (WHERE ${LEVEL}='dangerous')::int AS dangerous,
           COUNT(*) FILTER (WHERE ${LEVEL}='suspicious')::int AS suspicious
    FROM emails e ${LATEST} WHERE ${realUser()} AND e.scanned_at > NOW() - interval '24 hours'`)).rows[0];
  const m = (await query(`SELECT COALESCE(SUM(minutes_wasted),0)::int AS m FROM honeypot_sessions WHERE ${realUser('user_id')} AND started_at > NOW() - interval '24 hours'`)).rows[0];
  return { ...r, minutesWasted: m.m };
}

// Emails users said were safe although Genjutsu flagged them
async function mistakes(limit = 100) {
  return (await query(`
    SELECT o.override_id, o.email_id, COALESCE(NULLIF(o.original_level,'user_override'), sr.threat_type) AS original_level, o.new_level, o.note, o.overridden_at,
           u.email AS user_email, e.sender_email, e.subject, ROUND(e.confidence_score*100)::int AS score, sr.details,
           (SELECT status FROM threat_reviews r WHERE r.email_id = o.email_id ORDER BY r.reviewed_at DESC LIMIT 1) AS review
    FROM threat_overrides o
    JOIN emails e ON e.email_id = o.email_id
    JOIN users u ON u.user_id = e.user_id
    LEFT JOIN LATERAL (SELECT details, threat_type FROM scan_results WHERE email_id = e.email_id ORDER BY scan_timestamp DESC LIMIT 1) sr ON TRUE
    WHERE ${realUser('u.user_id')} AND lower(o.overridden_by) = lower(u.email) AND o.new_level = 'safe'
      AND COALESCE(NULLIF(o.original_level,'user_override'), sr.threat_type) IN ('dangerous','suspicious')
    ORDER BY o.overridden_at DESC LIMIT $1`, [limit])).rows;
}

// ── Users ────────────────────────────────────────────────────
async function userList() {
  return (await query(`
    SELECT u.user_id, u.email, u.username, u.picture, u.created_at, u.last_login, u.status, u.provider,
           u.last_scan_at, u.last_scan_error, u.last_scan_error_at,
           (u.user_id LIKE 'demo-%') AS demo,
           EXISTS (SELECT 1 FROM suspended_users s WHERE s.user_id = u.user_id) AS is_suspended,
           (SELECT COUNT(*)::int FROM emails e WHERE e.user_id = u.user_id) AS emails,
           (SELECT COUNT(*)::int FROM emails e WHERE e.user_id = u.user_id AND e.is_phishing = 1) AS threats
    FROM users u ${currentOrg() ? 'WHERE ' + realUser('u.user_id') : ''} ORDER BY u.last_login DESC NULLS LAST`)).rows;
}
async function problemUsers() {
  return (await query(`
    SELECT user_id, email, provider, last_scan_at, last_scan_error, last_scan_error_at, last_login
    FROM users
    WHERE ${realUser('user_id')} AND (
      (last_scan_error IS NOT NULL AND last_scan_error_at > NOW() - interval '7 days')
      OR (last_login > NOW() - interval '30 days' AND (last_scan_at IS NULL OR last_scan_at < NOW() - interval '7 days'))
    ) ORDER BY last_scan_error_at DESC NULLS LAST`)).rows;
}
async function userDetail(userId) {
  const [u, settings, stats, threats, hp, rules, safe, act, keys] = await Promise.all([
    query(`SELECT user_id, email, username, picture, created_at, last_login, status, provider, last_scan_at, last_scan_error, last_scan_error_at,
             EXISTS (SELECT 1 FROM suspended_users s WHERE s.user_id = users.user_id) AS is_suspended FROM users WHERE user_id=$1`, [userId]),
    query('SELECT auto_block, honeypot_mode, weekly_digest, honeypot_persona, (discord_webhook IS NOT NULL) AS discord FROM user_settings WHERE user_id=$1', [userId]).catch(() => ({ rows: [] })),
    query(`SELECT COUNT(*)::int AS emails, COUNT(*) FILTER (WHERE is_phishing=1)::int AS threats,
             (SELECT COUNT(*)::int FROM blocked_emails b WHERE b.user_id=$1 AND b.reason='auto') AS quarantined
           FROM emails WHERE user_id=$1`, [userId]),
    query(`SELECT e.email_id, e.sender_email, e.subject, e.scanned_at, ROUND(e.confidence_score*100)::int AS score, ${LEVEL} AS level, sr.origin_country
           FROM emails e ${LATEST} WHERE e.user_id=$1 AND ${LEVEL} IN ('dangerous','suspicious') ORDER BY e.scanned_at DESC LIMIT 20`, [userId]),
    query('SELECT session_id, sender_email, subject, status, replies_sent, minutes_wasted, started_at, persona, stop_reason FROM honeypot_sessions WHERE user_id=$1 ORDER BY started_at DESC LIMIT 20', [userId]),
    query('SELECT field, value, action FROM user_rules WHERE user_id=$1', [userId]),
    query('SELECT sender_email FROM user_safe_senders WHERE user_id=$1', [userId]),
    query('SELECT action, detail, at AS created_at FROM user_activity WHERE user_id=$1 ORDER BY at DESC LIMIT 20', [userId]),
    query('SELECT name, created_at, last_used FROM user_api_keys WHERE user_id=$1', [userId]),
  ]);
  if (!u.rows[0]) return null;
  return { user: u.rows[0], settings: settings.rows[0] || {}, stats: stats.rows[0], threats: threats.rows, honeypot: hp.rows,
    rules: rules.rows, safeSenders: safe.rows.map(r => r.sender_email), activity: act.rows, apiKeys: keys.rows };
}

// ── Honeypot across all users ───────────────────────────────
async function honeypotInbound() {
  return (await query(`
    SELECT s.session_id, s.sender_email, s.subject, u.email AS user_email, m.body, m.sent_at
    FROM honeypot_messages m JOIN honeypot_sessions s ON s.session_id = m.session_id
    LEFT JOIN users u ON u.user_id = s.user_id
    WHERE m.direction = 'inbound' AND ${realUser('s.user_id')} ORDER BY m.sent_at DESC LIMIT 2000`)).rows;
}
async function leaderboard() {
  return (await query(`
    SELECT u.email AS user_email, COUNT(*)::int AS sessions, COALESCE(SUM(s.minutes_wasted),0)::int AS minutes, COALESCE(SUM(s.replies_sent),0)::int AS replies
    FROM honeypot_sessions s JOIN users u ON u.user_id = s.user_id
    WHERE ${realUser('u.user_id')}
    GROUP BY u.email ORDER BY minutes DESC LIMIT 10`)).rows;
}

// ── Health ───────────────────────────────────────────────────
async function health() {
  const t0 = Date.now();
  let dbOk = true, dbMs = null;
  try { await query('SELECT 1'); dbMs = Date.now() - t0; } catch (_) { dbOk = false; }
  const safe = async (sql, d) => { try { return (await query(sql)).rows[0]; } catch (_) { return d; } };
  const last = await safe('SELECT MAX(scanned_at) AS at FROM emails', { at: null });
  const broken = await safe(`SELECT COUNT(*)::int AS n FROM users WHERE last_scan_error IS NOT NULL AND last_scan_error_at > NOW() - interval '24 hours'`, { n: 0 });
  const demo = await safe(`SELECT COUNT(*)::int AS n FROM users WHERE user_id LIKE 'demo-%'`, { n: 0 });
  let alerts = { discord: false, email: false, telegram: 'off', threatAlerts: true };
  try { alerts = await require('../services/teamAlerts').status(); } catch (_) {}
  return {
    db: { ok: dbOk, ms: dbMs },
    lastScanAt: last.at,
    brokenConnections24h: broken.n,
    ai: { configured: !!process.env.GROQ_API_KEY },
    safeBrowsing: { configured: !!process.env.SAFE_BROWSING_API_KEY },
    google: { configured: !!process.env.GOOGLE_CLIENT_ID },
    microsoft: { configured: !!process.env.MICROSOFT_CLIENT_ID },
    alerts,
    encryptionKey: process.env.MAIL_ENCRYPTION_KEY ? 'own key' : 'falls back to SESSION_SECRET',
    demoUsers: demo.n,
    uptimeMin: Math.round(process.uptime() / 60),
    node: process.version,
  };
}

// ── Totals for the Wall (all time, real accounts only) ───────
async function systemStats() {
  const one = async (sql) => (await query(sql)).rows[0];
  const [users, scans, hp, alerts, model, subtypes] = await Promise.all([
    one(`SELECT COUNT(*)::int AS n FROM users WHERE ${realUser('user_id')}`),
    one(`SELECT COUNT(*)::int AS emails,
                COUNT(*) FILTER (WHERE ${LEVEL}='dangerous')::int AS dangerous,
                COUNT(*) FILTER (WHERE ${LEVEL}='suspicious')::int AS suspicious
         FROM emails e ${LATEST} WHERE ${realUser()}`),
    one(`SELECT COUNT(*)::int AS total, COUNT(*) FILTER (WHERE status='active')::int AS active,
                COALESCE(SUM(CASE WHEN status='active' THEN GREATEST(0, EXTRACT(EPOCH FROM NOW()-started_at)/60)::int ELSE minutes_wasted END),0)::int AS minutes
         FROM honeypot_sessions WHERE ${realUser('user_id')}`),
    one(`SELECT COUNT(*)::int AS n FROM alerts WHERE ${realUser('user_id')}`),
    one(`SELECT * FROM ml_models WHERE is_active=1 LIMIT 1`),
    query(`SELECT COALESCE(sr.threat_subtype,'phishing') AS k, COUNT(*)::int AS n
           FROM emails e LEFT JOIN LATERAL (SELECT threat_type, threat_subtype FROM scan_results WHERE email_id=e.email_id ORDER BY scan_timestamp DESC LIMIT 1) sr ON TRUE
           LEFT JOIN LATERAL (SELECT new_level FROM threat_overrides WHERE email_id=e.email_id ORDER BY overridden_at DESC LIMIT 1) ov ON TRUE
           WHERE ${realUser()} AND COALESCE(ov.new_level, sr.threat_type) IN ('dangerous','suspicious') GROUP BY 1`).then(r => r.rows),
  ]);
  const sub = { phishing: 0, malware_link: 0, spoofed_sender: 0, other: 0 };
  for (const r of subtypes) sub[r.k in sub ? r.k : 'other'] += r.n;
  return {
    totalUsers: users.n, totalEmails: scans.emails, totalThreats: scans.dangerous + scans.suspicious,
    dangerousCount: scans.dangerous, suspiciousCount: scans.suspicious, subtypes: sub,
    totalHoneypot: hp.total, activeHoneypot: hp.active, totalMinutesWasted: hp.minutes,
    totalAlerts: alerts.n, activeModel: model ? { model_name: model.model_name, version: model.version, accuracy: model.accuracy } : null,
  };
}
// Last N days, by the Nepal day each email arrived (scan day if the date can't be read)
async function trend(days = 7) {
  const { recordToEmail, nptDay, NPT_MS } = require('../services/threatRecords');
  const rows = (await query(`SELECT e.received_date, e.scanned_at, ${LEVEL} AS level FROM emails e ${LATEST}
    WHERE ${realUser()} AND e.scanned_at > NOW() - ($1 || ' days')::interval - interval '1 day'`, [String(days)])).rows;
  const keys = [], labels = [];
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(Date.now() + NPT_MS - i * 864e5);
    keys.push(d.toISOString().slice(0, 10)); labels.push(d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', timeZone: 'UTC' }));
  }
  const threats = keys.map(() => 0), safe = keys.map(() => 0);
  for (const r of rows) {
    const k = keys.indexOf(nptDay(r.received_date) || nptDay(r.scanned_at));
    if (k < 0) continue;
    if (r.level === 'dangerous' || r.level === 'suspicious') threats[k]++; else safe[k]++;
  }
  return { labels, threats, safe };
}

// ── Monthly report ───────────────────────────────────────────
async function monthReport(year, month) {
  const from = new Date(Date.UTC(year, month - 1, 1)), to = new Date(Date.UTC(year, month, 1));
  const p = [from.toISOString(), to.toISOString()];
  const one = async (sql) => (await query(sql, p)).rows[0];
  const totals = await one(`
    SELECT COUNT(*)::int AS scanned,
           COUNT(*) FILTER (WHERE ${LEVEL}='dangerous')::int AS dangerous,
           COUNT(*) FILTER (WHERE ${LEVEL}='suspicious')::int AS suspicious,
           COUNT(DISTINCT e.user_id)::int AS users
    FROM emails e ${LATEST} WHERE ${realUser()} AND e.scanned_at >= $1 AND e.scanned_at < $2`);
  const quarantined = await one(`SELECT COUNT(*)::int AS n FROM blocked_emails WHERE ${realUser('user_id')} AND reason='auto' AND blocked_at >= $1 AND blocked_at < $2`);
  const hp = await one(`SELECT COUNT(*)::int AS sessions, COALESCE(SUM(minutes_wasted),0)::int AS minutes FROM honeypot_sessions WHERE ${realUser('user_id')} AND started_at >= $1 AND started_at < $2`);
  const newUsers = await one(`SELECT COUNT(*)::int AS n FROM users WHERE created_at >= $1 AND created_at < $2 AND ${realUser('user_id')}`);
  const attackers = (await query(`
    SELECT ${DOMAIN('e.sender_email')} AS domain, COUNT(DISTINCT e.user_id)::int AS users, COUNT(*)::int AS emails
    FROM emails e ${LATEST} WHERE ${realUser()} AND e.scanned_at >= $1 AND e.scanned_at < $2 AND ${LEVEL} IN ('dangerous','suspicious')
    GROUP BY 1 HAVING ${DOMAIN('e.sender_email')} <> '' ORDER BY users DESC, emails DESC LIMIT 8`, p)).rows;
  const countries = (await query(`
    SELECT COALESCE(sr.origin_country,'??') AS country, COUNT(*)::int AS n
    FROM emails e ${LATEST} WHERE ${realUser()} AND e.scanned_at >= $1 AND e.scanned_at < $2 AND ${LEVEL} IN ('dangerous','suspicious')
    GROUP BY 1 ORDER BY n DESC LIMIT 8`, p)).rows;
  const mitre = (await query(`
    SELECT sr.mitre FROM emails e ${LATEST} WHERE ${realUser()} AND e.scanned_at >= $1 AND e.scanned_at < $2 AND ${LEVEL} IN ('dangerous','suspicious')`, p)).rows;
  const disputes = await one(`
    SELECT COUNT(*)::int AS n FROM threat_overrides o JOIN emails e ON e.email_id=o.email_id JOIN users u ON u.user_id=e.user_id
    WHERE ${realUser('u.user_id')} AND lower(o.overridden_by)=lower(u.email) AND o.new_level='safe' AND o.overridden_at >= $1 AND o.overridden_at < $2`);
  return { from, to, totals, quarantined: quarantined.n, honeypot: hp, newUsers: newUsers.n, attackers, countries, mitreRows: mitre, disputes: disputes.n };
}

// ── Queue: items marked done ─────────────────────────────────
const doneKeys = async () => new Set((await query(`SELECT item_key FROM admin_queue_done WHERE done_at > NOW() - interval '30 days'`)).rows.map(r => r.item_key));
const markDone = (key, by) => query('INSERT INTO admin_queue_done (item_key, done_by) VALUES ($1,$2) ON CONFLICT (item_key) DO NOTHING', [key, by]);

module.exports = {
  DOMAIN, initAdminDb, hashPlainAdminPasswords,
  getAdminFull, getAdminById, setAdminPassword, setAdminTotp, setTotpStep, setRecoveryCodes, seenDevice, listDevices,
  listAnnouncements, activeAnnouncements, addAnnouncement, endAnnouncement,
  listBlocklist, addBlock, removeBlock,
  requestAction, listActions, getAction, decideAction,
  topAttackers, attackerDetail, origins, liveFeed, hourly, counts24h, mistakes,
  userList, problemUsers, userDetail, honeypotInbound, leaderboard, health, monthReport, doneKeys, markDone, systemStats, trend, realUser,
};
