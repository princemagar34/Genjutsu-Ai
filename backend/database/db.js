// ============================================================
// database/db.js — PostgreSQL Database (migrated from SQLite)
// ============================================================
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Cloud SQL via Unix socket does not use SSL — SSL only needed for TCP connections
  ssl: false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

// ── Helper: run a query ───────────────────────────────────────
async function query(text, params) {
  const client = await pool.connect();
  try {
    const res = await client.query(text, params);
    return res;
  } finally {
    client.release();
  }
}

// sync-style wrapper so existing code works without async changes
// Returns rows directly like better-sqlite3 did
function querySync(text, params) {
  throw new Error('Use async queryAsync instead: ' + text);
}

// ── Initialize all tables ─────────────────────────────────────
async function initDB() {
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      user_id       TEXT PRIMARY KEY,
      email         TEXT UNIQUE NOT NULL,
      username      TEXT,
      gmail_token   TEXT,
      refresh_token TEXT,
      picture       TEXT,
      created_at    TIMESTAMPTZ DEFAULT NOW(),
      last_login    TIMESTAMPTZ,
      status        TEXT DEFAULT 'active'
    );

    CREATE TABLE IF NOT EXISTS emails (
      email_id         TEXT PRIMARY KEY,
      user_id          TEXT NOT NULL,
      gmail_message_id TEXT,
      sender_email     TEXT,
      sender_name      TEXT,
      subject          TEXT,
      body_text        TEXT,
      received_date    TEXT,
      is_phishing      INTEGER DEFAULT 0,
      confidence_score REAL DEFAULT 0,
      scanned_at       TIMESTAMPTZ DEFAULT NOW(),
      spf_result       TEXT,
      dkim_result      TEXT,
      dmarc_result     TEXT,
      auth_raw         TEXT,
      has_attachment   INTEGER DEFAULT 0,
      FOREIGN KEY (user_id) REFERENCES users(user_id)
    );

    CREATE TABLE IF NOT EXISTS scan_results (
      scan_id             TEXT PRIMARY KEY,
      email_id            TEXT NOT NULL,
      scan_timestamp      TIMESTAMPTZ DEFAULT NOW(),
      scanner_type        TEXT,
      threat_detected     INTEGER DEFAULT 0,
      threat_type         TEXT,
      confidence_level    REAL DEFAULT 0,
      details             TEXT,
      url_scan_results    TEXT,
      attachment_scan     TEXT,
      FOREIGN KEY (email_id) REFERENCES emails(email_id)
    );

    CREATE TABLE IF NOT EXISTS alerts (
      alert_id   TEXT PRIMARY KEY,
      email_id   TEXT,
      user_id    TEXT,
      alert_type TEXT,
      message    TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      is_read    INTEGER DEFAULT 0,
      FOREIGN KEY (email_id) REFERENCES emails(email_id),
      FOREIGN KEY (user_id)  REFERENCES users(user_id)
    );

    CREATE TABLE IF NOT EXISTS ml_models (
      model_id   TEXT PRIMARY KEY,
      model_name TEXT,
      version    TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      accuracy   REAL,
      is_active  INTEGER DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS honeypot_sessions (
      session_id              TEXT PRIMARY KEY,
      user_id                 TEXT,
      email_id                TEXT,
      thread_id               TEXT,
      message_id              TEXT,
      references_hdr          TEXT,
      last_processed_msg_id   TEXT,
      sender_email            TEXT,
      subject                 TEXT,
      started_at              TIMESTAMPTZ DEFAULT NOW(),
      replies_sent            INTEGER DEFAULT 0,
      minutes_wasted          INTEGER DEFAULT 0,
      last_reply_at           TIMESTAMPTZ,
      status                  TEXT DEFAULT 'active',
      FOREIGN KEY (user_id) REFERENCES users(user_id)
    );

    CREATE TABLE IF NOT EXISTS honeypot_messages (
      message_id   TEXT PRIMARY KEY,
      session_id   TEXT NOT NULL,
      direction    TEXT NOT NULL CHECK(direction IN ('inbound','outbound')),
      from_address TEXT,
      body         TEXT,
      sent_at      TIMESTAMPTZ DEFAULT NOW(),
      gmail_msg_id TEXT,
      FOREIGN KEY (session_id) REFERENCES honeypot_sessions(session_id)
    );

    CREATE TABLE IF NOT EXISTS user_settings (
      user_id              TEXT PRIMARY KEY,
      real_time_alerts     INTEGER DEFAULT 1,
      email_notifications  INTEGER DEFAULT 1,
      sound_alerts         INTEGER DEFAULT 0,
      auto_block           INTEGER DEFAULT 1,
      multi_layer_scan     INTEGER DEFAULT 1,
      link_scanning        INTEGER DEFAULT 1,
      honeypot_mode        INTEGER DEFAULT 0,
      telegram_enabled     INTEGER DEFAULT 0,
      scan_frequency       TEXT DEFAULT 'realtime',
      updated_at           TIMESTAMPTZ DEFAULT NOW(),
      FOREIGN KEY (user_id) REFERENCES users(user_id)
    );

    CREATE TABLE IF NOT EXISTS admin_users (
      admin_id   TEXT PRIMARY KEY,
      email      TEXT UNIQUE NOT NULL,
      password   TEXT NOT NULL,
      role       TEXT DEFAULT 'viewer',
      name       TEXT,
      created_by TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      last_login TIMESTAMPTZ,
      is_active  INTEGER DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS threat_reviews (
      review_id   TEXT PRIMARY KEY,
      email_id    TEXT NOT NULL,
      reviewed_by TEXT NOT NULL,
      note        TEXT,
      status      TEXT DEFAULT 'reviewed',
      reviewed_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS activity_log (
      log_id      TEXT PRIMARY KEY,
      admin_email TEXT NOT NULL,
      admin_role  TEXT,
      action      TEXT NOT NULL,
      detail      TEXT,
      ip_address  TEXT,
      logged_at   TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS system_settings (
      key        TEXT PRIMARY KEY,
      value      TEXT NOT NULL,
      updated_by TEXT,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS suspended_users (
      user_id      TEXT PRIMARY KEY,
      email        TEXT NOT NULL,
      reason       TEXT,
      suspended_by TEXT,
      suspended_at TIMESTAMPTZ DEFAULT NOW(),
      is_active    INTEGER DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS threat_overrides (
      override_id   TEXT PRIMARY KEY,
      email_id      TEXT NOT NULL,
      original_level TEXT,
      new_level     TEXT,
      overridden_by TEXT,
      note          TEXT,
      overridden_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS remark_notifications (
      remark_notif_id TEXT PRIMARY KEY,
      user_id         TEXT NOT NULL,
      email_id        TEXT NOT NULL,
      override_id     TEXT NOT NULL,
      note            TEXT,
      new_level       TEXT,
      overridden_by   TEXT,
      is_read         INTEGER DEFAULT 0,
      created_at      TIMESTAMPTZ DEFAULT NOW(),
      FOREIGN KEY (user_id) REFERENCES users(user_id)
    );

    CREATE TABLE IF NOT EXISTS blocked_emails (
      block_id        TEXT PRIMARY KEY,
      user_id         TEXT NOT NULL,
      email_id        TEXT NOT NULL,
      sender_email    TEXT,
      subject         TEXT,
      gmail_msg_id    TEXT,
      blocked_at      TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (user_id, email_id),
      FOREIGN KEY (user_id) REFERENCES users(user_id)
    );
  `);

  // ── CHANGE: Add threat_subtype column if it doesn't exist yet ────────────
  // This stores the sub-category of each threat: phishing | malware_link |
  // spoofed_sender | other. Safe emails store NULL.
  // Using ADD COLUMN IF NOT EXISTS makes this safe to run on every startup.
  await query(`
    ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS threat_subtype TEXT;
  `);

  // Seed default ML model
  await query(`
    INSERT INTO ml_models (model_id, model_name, version, accuracy, is_active)
    VALUES ('model-v1', 'Genjutsu Naive Bayes Classifier', '1.0.0', 0.89, 1)
    ON CONFLICT (model_id) DO NOTHING
  `);

  // Seed default system settings
  const defaults = [
    ['threat_score_dangerous',  '60'],
    ['threat_score_suspicious', '30'],
    ['max_emails_scan',         '50'],
    ['honeypot_enabled',        'true'],
    ['telegram_alerts',         'true'],
    ['scan_on_login',           'true'],
  ];
  for (const [k, v] of defaults) {
    await query(
      `INSERT INTO system_settings (key, value, updated_by)
       VALUES ($1, $2, 'system') ON CONFLICT (key) DO NOTHING`,
      [k, v]
    );
  }

  // Seed super admin from .env
  await seedSuperAdmin();

  console.log('✅ PostgreSQL tables ready');
}

async function seedSuperAdmin() {
  const email    = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;
  if (!email || !password) return;

  await query(`
    INSERT INTO admin_users (admin_id, email, password, role, name, created_by)
    VALUES ('superadmin-1', $1, $2, 'superadmin', 'Super Admin', 'system')
    ON CONFLICT (email) DO UPDATE SET role = 'superadmin'
  `, [email, password]);
  console.log(`✅ Super admin ready: ${email}`);
}

// ── User helpers ─────────────────────────────────────────────

async function upsertUser(user) {
  await query(`
    INSERT INTO users (user_id, email, username, gmail_token, refresh_token, picture, last_login)
    VALUES ($1, $2, $3, $4, $5, $6, NOW())
    ON CONFLICT (user_id) DO UPDATE SET
      gmail_token   = EXCLUDED.gmail_token,
      refresh_token = EXCLUDED.refresh_token,
      last_login    = NOW()
  `, [user.id, user.email, user.name, user.accessToken, user.refreshToken || null, user.picture || null]);

  await query(
    `INSERT INTO user_settings (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING`,
    [user.id]
  );
}

async function saveEmailScan(email, threat, userId) {
  const emailId = `${userId}-${email.id}`;
  const scanId  = `scan-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;
  // ── FIX: alertId is now deterministic based on emailId ───────
  // Previously it used Date.now()+random so ON CONFLICT never fired,
  // causing a new alert row on every scan → 23,000+ duplicate alerts.
  // Now the same email always produces the same alertId, so re-scanning
  // the same email never creates a duplicate alert.
  const alertId = `alert-${emailId}`;

  const authRaw    = threat.authDetails?.raw || '';
  const spfResult  = (authRaw.match(/spf=(pass|fail|softfail|neutral|none)/i)  || [])[1] || null;
  const dkimResult = (authRaw.match(/dkim=(pass|fail|neutral|none)/i)           || [])[1] || null;
  const dmarcResult= (authRaw.match(/dmarc=(pass|fail|none)/i)                  || [])[1] || null;

  await query(`
    INSERT INTO emails
      (email_id, user_id, gmail_message_id, sender_email, subject, body_text,
       received_date, is_phishing, confidence_score, scanned_at,
       spf_result, dkim_result, dmarc_result, auth_raw, has_attachment)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW(),$10,$11,$12,$13,$14)
    ON CONFLICT (email_id) DO UPDATE SET
      is_phishing      = EXCLUDED.is_phishing,
      confidence_score = EXCLUDED.confidence_score,
      scanned_at       = NOW()
  `, [
    emailId, userId, email.id, email.from, email.subject,
    (email.body || '').substring(0, 1000),
    email.date, threat.level !== 'safe' ? 1 : 0, threat.score / 100,
    spfResult, dkimResult, dmarcResult, authRaw.substring(0, 500),
    (email.attachments || []).length > 0 ? 1 : 0
  ]);

  const suspiciousUrls = (email.links || []).filter(link =>
    /paypa1\.com|g00gle\.com|amaz0n\.com|micros0ft\.com|secure-login\.|account-verify\.|login-confirm\.|verify-account\.|https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}/.test(link)
  );

  await query(`
    INSERT INTO scan_results
      (scan_id, email_id, scanner_type, threat_detected, threat_type, threat_subtype,
       confidence_level, details, url_scan_results, attachment_scan)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
    ON CONFLICT (scan_id) DO NOTHING
  `, [
    scanId, emailId, 'multi-layer-nlp',
    threat.level !== 'safe' ? 1 : 0,
    threat.level,
    threat.subType || null,           // ← CHANGE: store sub-type label
    threat.score / 100,
    JSON.stringify(threat.reasons),
    JSON.stringify(suspiciousUrls),
    JSON.stringify(threat.attachmentDetails || [])
  ]);

  if (threat.level !== 'safe') {
    await query(`
      INSERT INTO alerts (alert_id, email_id, user_id, alert_type, message)
      VALUES ($1,$2,$3,$4,$5) ON CONFLICT (alert_id) DO NOTHING
    `, [alertId, emailId, userId, threat.level,
        `${threat.level.toUpperCase()}: "${email.subject}" from ${email.from}`]);
  }
}

async function getAlerts(userId, limit = 20) {
  const res = await query(`
    SELECT a.*, e.subject, e.sender_email
    FROM alerts a
    LEFT JOIN emails e ON a.email_id = e.email_id
    WHERE a.user_id = $1 AND a.is_read = 0
    ORDER BY a.created_at DESC LIMIT $2
  `, [userId, limit]);
  return res.rows;
}

async function markAlertRead(alertId) {
  await query('UPDATE alerts SET is_read = 1 WHERE alert_id = $1', [alertId]);
}

async function markAllAlertsRead(userId) {
  await query('UPDATE alerts SET is_read = 1 WHERE user_id = $1', [userId]);
}

async function getScanHistory(userId, days = 7) {
  // Fetch raw rows and parse received_date in Node.js.
  // This avoids SQL to_timestamp() errors caused by Gmail's varied date formats
  // (e.g. "Sat, 22 Mar 2025 14:30:00 +0545" vs "22 Mar 2025 09:00:00 GMT").
  // We bucket each email by its received date (in Nepal time) so the 7-day
  // chart reflects when emails arrived, not just when the user first ran a scan.

  const NPT_OFFSET_MS = (5 * 60 + 45) * 60 * 1000; // UTC+5:45

  const res = await query(`
    SELECT DISTINCT ON (gmail_message_id)
           email_id, gmail_message_id, is_phishing, scanned_at, received_date,
           (SELECT threat_type FROM scan_results WHERE email_id = e.email_id
            ORDER BY scan_timestamp DESC LIMIT 1) AS threat_type
    FROM emails e
    WHERE user_id = $1
      AND gmail_message_id IS NOT NULL
      AND scanned_at >= NOW() - ($2 || ' days')::INTERVAL
    ORDER BY gmail_message_id, scanned_at DESC
  `, [userId, days]);

  // Build a map: YYYY-MM-DD (NPT) → { total, threats, dangerous, suspicious, safe }
  const buckets = {};
  const cutoffMs = Date.now() + NPT_OFFSET_MS - days * 24 * 60 * 60 * 1000;

  for (const row of res.rows) {
    // Try received_date first; fall back to scanned_at
    let ts = null;
    if (row.received_date) {
      const parsed = new Date(row.received_date);
      if (!isNaN(parsed.getTime())) ts = parsed.getTime();
    }
    if (!ts && row.scanned_at) {
      ts = new Date(row.scanned_at).getTime();
    }
    if (!ts) continue;

    // Only include emails within the requested window
    if (ts < cutoffMs) continue;

    // Convert to NPT date string YYYY-MM-DD
    const nptDate = new Date(ts + NPT_OFFSET_MS).toISOString().split('T')[0];

    if (!buckets[nptDate]) {
      buckets[nptDate] = { total: 0, threats: 0, dangerous: 0, suspicious: 0, safe: 0 };
    }
    const b = buckets[nptDate];
    b.total++;
    const tt = row.threat_type || '';
    if (tt === 'dangerous')       { b.dangerous++;  b.threats++; }
    else if (tt === 'suspicious') { b.suspicious++; b.threats++; }
    else                           b.safe++;
  }

  // Return as array sorted by date ascending (same shape as before)
  return Object.entries(buckets)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([scan_date, counts]) => ({ scan_date, ...counts }));
}

async function getReportData(userId) {
  const user = (await query('SELECT * FROM users WHERE user_id = $1', [userId])).rows[0];

  // ── Deduplicated emails with latest scan + override ──────────
  const emailRows = (await query(`
    SELECT e.email_id, e.gmail_message_id, e.sender_email, e.subject,
           e.received_date, e.is_phishing, e.confidence_score, e.scanned_at,
           s.threat_type, s.details,
           ov.new_level AS override_level
    FROM (
      SELECT DISTINCT ON (gmail_message_id)
             email_id, gmail_message_id, sender_email, subject,
             received_date, is_phishing, confidence_score, scanned_at
      FROM emails
      WHERE user_id = $1 AND gmail_message_id IS NOT NULL
      ORDER BY gmail_message_id, scanned_at DESC
    ) e
    LEFT JOIN LATERAL (
      SELECT threat_type, details
      FROM scan_results
      WHERE email_id = e.email_id
      ORDER BY scan_timestamp DESC LIMIT 1
    ) s ON TRUE
    LEFT JOIN LATERAL (
      SELECT new_level
      FROM threat_overrides
      WHERE email_id = e.email_id
      ORDER BY overridden_at DESC LIMIT 1
    ) ov ON TRUE
    ORDER BY e.scanned_at DESC
    LIMIT 200
  `, [userId])).rows;

  // ── Apply overrides to get effective threat level ─────────────
  const emails = emailRows.map(e => {
    const effectiveLevel = e.override_level || e.threat_type ||
      (parseInt(e.is_phishing) === 1 ? 'suspicious' : 'safe');
    return {
      ...e,
      is_phishing: effectiveLevel !== 'safe' ? 1 : 0,
      threat_type: effectiveLevel
    };
  });

  const threats = emails.filter(e => e.is_phishing === 1).length;
  const stats   = { total: emails.length, threats, safe: emails.length - threats };

  const honeypot = (await query(`
    SELECT COUNT(*) as sessions, COALESCE(SUM(minutes_wasted),0) as minutes
    FROM honeypot_sessions WHERE user_id = $1
  `, [userId])).rows[0];

  return { user, emails, stats, honeypot };
}


async function getSettings(userId) {
  const res = await query('SELECT * FROM user_settings WHERE user_id = $1', [userId]);
  return res.rows[0] || {
    user_id: userId, real_time_alerts: 1, email_notifications: 1,
    sound_alerts: 0, auto_block: 1, multi_layer_scan: 1,
    link_scanning: 1, honeypot_mode: 0, scan_frequency: 'realtime'
  };
}

async function updateSettings(userId, updates) {
  const allowed = ['real_time_alerts','email_notifications','sound_alerts',
                   'auto_block','multi_layer_scan','link_scanning',
                   'honeypot_mode','scan_frequency','telegram_enabled'];
  const filtered = Object.fromEntries(
    Object.entries(updates).filter(([k]) => allowed.includes(k))
  );
  if (!Object.keys(filtered).length) return;
  const keys    = Object.keys(filtered);
  const values  = Object.values(filtered);
  const setClauses = keys.map((k, i) => `${k} = $${i + 1}`).join(', ');
  await query(
    `UPDATE user_settings SET ${setClauses}, updated_at=NOW() WHERE user_id=$${keys.length + 1}`,
    [...values, userId]
  );
}

// ── Honeypot helpers ─────────────────────────────────────────

async function saveHoneypotSession(session) {
  await query(`
    INSERT INTO honeypot_sessions
      (session_id, user_id, email_id, thread_id, message_id, references_hdr,
       sender_email, subject, replies_sent, minutes_wasted, started_at, last_reply_at, status)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
    ON CONFLICT (session_id) DO UPDATE SET
      replies_sent  = EXCLUDED.replies_sent,
      minutes_wasted= EXCLUDED.minutes_wasted,
      last_reply_at = EXCLUDED.last_reply_at,
      status        = EXCLUDED.status
  `, [
    session.session_id, session.user_id, session.email_id,
    session.thread_id    || null,
    session.message_id   || null,
    session.references_hdr || null,
    session.sender_email, session.subject,
    session.replies_sent, session.minutes_wasted,
    session.started_at   || new Date().toISOString(),
    session.last_reply_at|| new Date().toISOString(),
    session.status || 'active'
  ]);
}

async function getHoneypotSessions(userId, includeEnded = false) {
  const whereStatus = includeEnded ? '' : `AND status = 'active'`;
  const res = await query(`
    SELECT * FROM honeypot_sessions
    WHERE user_id = $1 ${whereStatus}
    ORDER BY started_at DESC
  `, [userId]);
  return res.rows;
}

async function endHoneypotSession(sessionId) {
  await query(`UPDATE honeypot_sessions SET status='ended' WHERE session_id=$1`, [sessionId]);
}

async function updateHoneypotSession(sessionId, fields = {}) {
  const allowed = ['minutes_wasted','replies_sent','status','last_reply_at',
                   'references_hdr','last_processed_msg_id'];
  const filtered = Object.fromEntries(
    Object.entries(fields).filter(([k]) => allowed.includes(k))
  );
  if (!Object.keys(filtered).length) return;
  const keys = Object.keys(filtered);
  const vals = Object.values(filtered);
  const setClauses = keys.map((k, i) => `${k} = $${i + 1}`).join(', ');
  await query(
    `UPDATE honeypot_sessions SET ${setClauses} WHERE session_id = $${keys.length + 1}`,
    [...vals, sessionId]
  );
}

async function getHoneypotSessionById(sessionId) {
  const res = await query('SELECT * FROM honeypot_sessions WHERE session_id = $1', [sessionId]);
  return res.rows[0];
}

async function getAllHoneypotSessions() {
  const res = await query(`
    SELECT h.*, u.email as user_email, u.username as user_name
    FROM honeypot_sessions h
    LEFT JOIN users u ON h.user_id = u.user_id
    ORDER BY h.started_at DESC
  `);
  return res.rows;
}

async function saveHoneypotMessage({ sessionId, direction, fromAddress, body, gmailMsgId }) {
  const id = `hpm-${Date.now()}-${Math.random().toString(36).substr(2, 7)}`;
  await query(`
    INSERT INTO honeypot_messages
      (message_id, session_id, direction, from_address, body, sent_at, gmail_msg_id)
    VALUES ($1,$2,$3,$4,$5,NOW(),$6)
  `, [id, sessionId, direction, fromAddress || '', (body || '').substring(0, 2000), gmailMsgId || null]);
}

async function getHoneypotMessages(sessionId) {
  const res = await query(`
    SELECT * FROM honeypot_messages
    WHERE session_id = $1 ORDER BY sent_at ASC
  `, [sessionId]);
  return res.rows;
}

async function getHoneypotMessagesBulk(sessionIds) {
  if (!sessionIds || sessionIds.length === 0) return [];
  const placeholders = sessionIds.map((_, i) => `$${i + 1}`).join(',');
  const res = await query(`
    SELECT * FROM honeypot_messages
    WHERE session_id IN (${placeholders})
    ORDER BY session_id, sent_at ASC
  `, sessionIds);
  return res.rows;
}

// ── Admin helpers ────────────────────────────────────────────

async function getAllUsers() {
  const res = await query(
    'SELECT user_id, email, username, picture, created_at, last_login, status FROM users ORDER BY created_at DESC'
  );
  return res.rows;
}

async function getAllThreats(limit = 100) {
  const res = await query(`
    SELECT e.email_id, e.sender_email, e.subject, e.received_date,
           e.is_phishing, e.confidence_score, e.scanned_at,
           e.gmail_message_id,
           s.threat_type, s.details, u.email as user_email
    FROM (
      SELECT DISTINCT ON (gmail_message_id, user_id)
             email_id, user_id, sender_email, subject, received_date,
             is_phishing, confidence_score, scanned_at, gmail_message_id
      FROM emails
      WHERE is_phishing = 1 AND gmail_message_id IS NOT NULL
      ORDER BY gmail_message_id, user_id, scanned_at DESC
    ) e
    LEFT JOIN LATERAL (
      SELECT threat_type, details
      FROM scan_results
      WHERE email_id = e.email_id
      ORDER BY scan_timestamp DESC LIMIT 1
    ) s ON TRUE
    LEFT JOIN users u ON e.user_id = u.user_id
    ORDER BY e.scanned_at DESC
    LIMIT $1
  `, [limit]);
  return res.rows;
}

// ── Admin trend data — real per-day counts across ALL users ──
// Used by the admin panel Threat Trend chart instead of fake estimates.
async function getAdminTrendData(days = 7) {
  const NPT_OFFSET_MS = (5 * 60 + 45) * 60 * 1000; // UTC+5:45

  const res = await query(`
    SELECT DISTINCT ON (gmail_message_id, user_id)
           email_id, gmail_message_id, user_id, is_phishing, scanned_at, received_date,
           (SELECT threat_type FROM scan_results sr
            WHERE sr.email_id = e.email_id
            ORDER BY sr.scan_timestamp DESC LIMIT 1) AS threat_type
    FROM emails e
    WHERE gmail_message_id IS NOT NULL
      AND scanned_at >= NOW() - ($1 || ' days')::INTERVAL
    ORDER BY gmail_message_id, user_id, scanned_at DESC
  `, [days]);

  const buckets  = {};
  const cutoffMs = Date.now() + NPT_OFFSET_MS - days * 24 * 60 * 60 * 1000;

  for (const row of res.rows) {
    let ts = null;
    if (row.received_date) {
      const parsed = new Date(row.received_date);
      if (!isNaN(parsed.getTime())) ts = parsed.getTime();
    }
    if (!ts && row.scanned_at) ts = new Date(row.scanned_at).getTime();
    if (!ts || ts < cutoffMs) continue;

    const nptDate = new Date(ts + NPT_OFFSET_MS).toISOString().split('T')[0];
    if (!buckets[nptDate]) buckets[nptDate] = { threats: 0, safe: 0 };

    const tt = row.threat_type || '';
    if (tt === 'dangerous' || tt === 'suspicious') buckets[nptDate].threats++;
    else buckets[nptDate].safe++;
  }

  // Build 7-day array with zeroes for missing days
  const labels  = [];
  const threats = [];
  const safe    = [];

  for (let i = days - 1; i >= 0; i--) {
    const nowNPT = new Date(Date.now() + NPT_OFFSET_MS);
    nowNPT.setUTCHours(0, 0, 0, 0);
    nowNPT.setUTCDate(nowNPT.getUTCDate() - i);
    const key   = nowNPT.toISOString().split('T')[0];
    const label = nowNPT.toLocaleDateString('en-US', { weekday: 'short' });
    labels.push(label);
    threats.push(buckets[key]?.threats || 0);
    safe.push(buckets[key]?.safe    || 0);
  }

  return { labels, threats, safe };
}

async function getSystemStats() {
  const [users, emails, threats, honeypot, activeHp, minutes, alertsR, model, levelCounts, subtypeCounts] = await Promise.all([
    query('SELECT COUNT(*) as c FROM users'),
    query('SELECT COUNT(*) as c FROM emails'),
    query('SELECT COUNT(DISTINCT gmail_message_id) as c FROM emails WHERE is_phishing=1'),
    query('SELECT COUNT(*) as c FROM honeypot_sessions'),
    query(`SELECT COUNT(*) as c FROM honeypot_sessions WHERE status='active'`),
    query('SELECT COALESCE(SUM(minutes_wasted),0) as c FROM honeypot_sessions'),
    query('SELECT COUNT(*) as c FROM alerts'),
    query('SELECT * FROM ml_models WHERE is_active=1 LIMIT 1'),
    // Real dangerous vs suspicious split for score distribution bar
    query(`
      SELECT sr.threat_type, COUNT(DISTINCT e.gmail_message_id) as c
      FROM scan_results sr
      JOIN emails e ON sr.email_id = e.email_id
      WHERE sr.threat_detected = 1 AND sr.threat_type IN ('dangerous','suspicious')
      GROUP BY sr.threat_type
    `),
    // Real subtype counts for pie chart
    query(`
      SELECT COALESCE(sr.threat_subtype, 'phishing') as subtype,
             COUNT(DISTINCT e.gmail_message_id) as c
      FROM scan_results sr
      JOIN emails e ON sr.email_id = e.email_id
      WHERE sr.threat_detected = 1
      GROUP BY sr.threat_subtype
    `)
  ]);

  // Parse dangerous/suspicious level counts
  const lvl = { dangerous: 0, suspicious: 0 };
  levelCounts.rows.forEach(r => { lvl[r.threat_type] = parseInt(r.c); });

  // Parse subtype counts
  const sub = { phishing: 0, malware_link: 0, spoofed_sender: 0, other: 0 };
  subtypeCounts.rows.forEach(r => {
    const k = r.subtype || 'phishing';
    if (sub.hasOwnProperty(k)) sub[k] = parseInt(r.c);
    else sub.other += parseInt(r.c);
  });

  return {
    totalUsers:         parseInt(users.rows[0].c),
    totalEmails:        parseInt(emails.rows[0].c),
    totalThreats:       parseInt(threats.rows[0].c),
    totalHoneypot:      parseInt(honeypot.rows[0].c),
    activeHoneypot:     parseInt(activeHp.rows[0].c),
    totalMinutesWasted: parseInt(minutes.rows[0].c),
    totalAlerts:        parseInt(alertsR.rows[0].c),
    activeModel:        model.rows[0],
    // Real counts — used by admin charts instead of fake estimates
    dangerousCount:     lvl.dangerous,
    suspiciousCount:    lvl.suspicious,
    subtypes:           sub   // { phishing, malware_link, spoofed_sender, other }
  };
}

async function getAdminByEmail(email) {
  const res = await query(
    'SELECT * FROM admin_users WHERE email = $1 AND is_active = 1', [email]
  );
  return res.rows[0];
}

async function getAllAdmins() {
  const res = await query(`
    SELECT admin_id, email, role, name, created_by, created_at, last_login, is_active
    FROM admin_users ORDER BY created_at ASC
  `);
  return res.rows;
}

async function createAdmin(admin) {
  const id = 'admin-' + Date.now();
  await query(`
    INSERT INTO admin_users (admin_id, email, password, role, name, created_by)
    VALUES ($1,$2,$3,$4,$5,$6)
  `, [id, admin.email, admin.password, admin.role || 'viewer', admin.name || '', admin.createdBy || 'superadmin']);
  return id;
}

async function updateAdminRole(adminId, role) {
  await query('UPDATE admin_users SET role = $1 WHERE admin_id = $2', [role, adminId]);
}

async function updateAdminLastLogin(email) {
  await query('UPDATE admin_users SET last_login = NOW() WHERE email = $1', [email]);
}

async function deleteAdmin(adminId) {
  await query(
    `UPDATE admin_users SET is_active = 0 WHERE admin_id = $1 AND created_by != 'system'`,
    [adminId]
  );
}

async function toggleAdminStatus(adminId) {
  await query(`
    UPDATE admin_users SET is_active = CASE WHEN is_active=1 THEN 0 ELSE 1 END
    WHERE admin_id = $1 AND created_by != 'system'
  `, [adminId]);
}

// ── Threat review helpers ─────────────────────────────────────

async function addThreatReview(emailId, adminEmail, note, status = 'reviewed') {
  const id = `rev-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`;
  await query(`
    INSERT INTO threat_reviews (review_id, email_id, reviewed_by, note, status)
    VALUES ($1,$2,$3,$4,$5)
    ON CONFLICT (review_id) DO NOTHING
  `, [id, emailId, adminEmail, note || '', status]);
}

async function getThreatReview(emailId) {
  const res = await query(
    'SELECT * FROM threat_reviews WHERE email_id=$1 ORDER BY reviewed_at DESC LIMIT 1',
    [emailId]
  );
  return res.rows[0];
}

async function getAllReviews() {
  const res = await query(`
    SELECT tr.*, e.subject, e.sender_email, u.email as user_email
    FROM threat_reviews tr
    LEFT JOIN emails e ON tr.email_id = e.email_id
    LEFT JOIN users  u ON e.user_id   = u.user_id
    ORDER BY tr.reviewed_at DESC LIMIT 100
  `);
  return res.rows;
}

// ── Activity log helpers ──────────────────────────────────────

async function logActivity(adminEmail, adminRole, action, detail, ip) {
  const id = `log-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`;
  await query(`
    INSERT INTO activity_log (log_id, admin_email, admin_role, action, detail, ip_address)
    VALUES ($1,$2,$3,$4,$5,$6)
  `, [id, adminEmail, adminRole, action, detail || '', ip || '']);
}

async function getActivityLog(limit = 100) {
  const res = await query(
    'SELECT * FROM activity_log ORDER BY logged_at DESC LIMIT $1', [limit]
  );
  return res.rows;
}

async function getAdminActivityLog(limit = 100) {
  const res = await query(`
    SELECT * FROM activity_log
    WHERE action LIKE 'ADMIN_%' OR action LIKE 'LOGIN%'
    ORDER BY logged_at DESC LIMIT $1
  `, [limit]);
  return res.rows;
}

// ── System settings helpers ───────────────────────────────────

async function getSystemSetting(key) {
  const res = await query('SELECT value FROM system_settings WHERE key=$1', [key]);
  return res.rows[0] ? res.rows[0].value : null;
}

async function getAllSystemSettings() {
  const res = await query('SELECT * FROM system_settings');
  return res.rows;
}

async function updateSystemSetting(key, value, updatedBy) {
  await query(`
    INSERT INTO system_settings (key, value, updated_by, updated_at)
    VALUES ($1,$2,$3,NOW())
    ON CONFLICT (key) DO UPDATE SET
      value      = EXCLUDED.value,
      updated_by = EXCLUDED.updated_by,
      updated_at = NOW()
  `, [key, value, updatedBy]);
}

// ── Suspend helpers ───────────────────────────────────────────

async function getUserByEmail(email) {
  const result = await query(
    'SELECT user_id, email, username, picture, status, created_at, last_login FROM users WHERE email = $1',
    [email]
  );
  return result.rows[0] || null;
}

async function suspendUser(userId, email, reason, adminEmail) {
  await query(`
    INSERT INTO suspended_users (user_id, email, reason, suspended_by)
    VALUES ($1,$2,$3,$4)
    ON CONFLICT (user_id) DO UPDATE SET
      reason       = EXCLUDED.reason,
      suspended_by = EXCLUDED.suspended_by,
      is_active    = 1
  `, [userId, email, reason || '', adminEmail]);
  await query(`UPDATE users SET status='suspended' WHERE user_id=$1`, [userId]);
}

async function unsuspendUser(userId) {
  await query(`UPDATE suspended_users SET is_active=0 WHERE user_id=$1`, [userId]);
  await query(`UPDATE users SET status='active' WHERE user_id=$1`, [userId]);
}

async function getSuspendedUsers() {
  const res = await query('SELECT * FROM suspended_users WHERE is_active=1');
  return res.rows;
}

// ── Threat override helpers ───────────────────────────────────

async function overrideThreatLevel(emailId, originalLevel, newLevel, adminEmail, note) {
  const id = `ov-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`;
  await query(`
    INSERT INTO threat_overrides
      (override_id, email_id, original_level, new_level, overridden_by, note)
    VALUES ($1,$2,$3,$4,$5,$6)
  `, [id, emailId, originalLevel, newLevel, adminEmail, note || '']);
  await query(
    `UPDATE emails SET is_phishing=$1 WHERE email_id=$2`,
    [newLevel !== 'safe' ? 1 : 0, emailId]
  );

  // ── Create a remark notification for the email's owner ───────
  // Always notify the user about the override (even without a custom remark)
  try {
    const emailRow = await query('SELECT user_id FROM emails WHERE email_id=$1', [emailId]);
    const userId   = emailRow.rows[0]?.user_id;
    if (userId) {
      const notifyNote = (note && note.trim())
        ? note.trim()
        : `An admin has reviewed and reclassified this email to "${newLevel}".`;
      const rnId = `rn-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;
      await query(`
        INSERT INTO remark_notifications
          (remark_notif_id, user_id, email_id, override_id, note, new_level, overridden_by)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
      `, [rnId, userId, emailId, id, notifyNote, newLevel, adminEmail]);
    }
  } catch (_) { /* non-critical — don't block the override */ }
}

// ── User self-override (no admin required) ───────────────────
// Stored in threat_overrides with overridden_by = user's email
// so it's distinguishable from admin overrides in the DB
async function userOverrideThreatLevel(emailId, newLevel, userId, note) {
  // Look up the user's email for the log
  const userRow = await query('SELECT email FROM users WHERE user_id=$1', [userId]);
  const userEmail = userRow.rows[0]?.email || userId;

  // Verify the email exists in DB (email_id = userId-gmailId so it always belongs to this user)
  const emailRow = await query('SELECT email_id FROM emails WHERE email_id=$1', [emailId]);
  if (!emailRow.rows[0]) throw new Error('Email not found. Please click Scan Now first to scan your inbox.');

  const id = `uov-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`;

  await query(`
    INSERT INTO threat_overrides
      (override_id, email_id, original_level, new_level, overridden_by, note)
    VALUES ($1,$2,'user_override',$3,$4,$5)
  `, [id, emailId, newLevel, userEmail, note || '']);

  // Update is_phishing flag
  await query(
    'UPDATE emails SET is_phishing=$1 WHERE email_id=$2',
    [newLevel !== 'safe' ? 1 : 0, emailId]
  );
}

async function getThreatOverride(emailId) {
  const res = await query(
    'SELECT * FROM threat_overrides WHERE email_id=$1 ORDER BY overridden_at DESC LIMIT 1',
    [emailId]
  );
  return res.rows[0];
}


// ── Remark notification helpers ───────────────────────────────

async function getUnreadRemarks(userId) {
  const res = await query(`
    SELECT rn.*, e.subject, e.sender_email
    FROM remark_notifications rn
    LEFT JOIN emails e ON rn.email_id = e.email_id
    WHERE rn.user_id = $1 AND rn.is_read = 0
    ORDER BY rn.created_at DESC
    LIMIT 20
  `, [userId]);
  return res.rows;
}

async function markRemarksRead(userId) {
  await query(
    'UPDATE remark_notifications SET is_read = 1 WHERE user_id = $1',
    [userId]
  );
}

// ── Export ───────────────────────────────────────────────────

// ── Blocked emails helpers ─────────────────────────────────

async function blockEmail(userId, emailId, gmailMsgId, senderEmail, subject) {
  const id = `blk-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`;
  await query(`
    INSERT INTO blocked_emails (block_id, user_id, email_id, gmail_msg_id, sender_email, subject)
    VALUES ($1,$2,$3,$4,$5,$6)
    ON CONFLICT (user_id, email_id) DO NOTHING
  `, [id, userId, emailId, gmailMsgId || '', senderEmail || '', subject || '']);
}

async function unblockEmail(userId, emailId) {
  await query(
    'DELETE FROM blocked_emails WHERE user_id=$1 AND email_id=$2',
    [userId, emailId]
  );
}

async function getBlockedEmails(userId) {
  const res = await query(
    'SELECT * FROM blocked_emails WHERE user_id=$1 ORDER BY blocked_at DESC',
    [userId]
  );
  return res.rows;
}

async function isEmailBlocked(userId, emailId) {
  const res = await query(
    'SELECT 1 FROM blocked_emails WHERE user_id=$1 AND email_id=$2',
    [userId, emailId]
  );
  return res.rows.length > 0;
}

module.exports = {
  pool, query, initDB,
  upsertUser, getUserByEmail, saveEmailScan, getAlerts, markAlertRead, markAllAlertsRead,
  getUnreadRemarks, markRemarksRead,
  getScanHistory, getAdminTrendData, getReportData, getSettings, updateSettings,
  saveHoneypotSession, getHoneypotSessions, endHoneypotSession,
  updateHoneypotSession, getHoneypotSessionById, getAllHoneypotSessions,
  saveHoneypotMessage, getHoneypotMessages, getHoneypotMessagesBulk,
  getAllUsers, getAllThreats, getSystemStats,
  getAdminByEmail, getAllAdmins, createAdmin,
  updateAdminRole, updateAdminLastLogin, deleteAdmin, toggleAdminStatus,
  addThreatReview, getThreatReview, getAllReviews,
  logActivity, getActivityLog, getAdminActivityLog,
  getSystemSetting, getAllSystemSettings, updateSystemSetting,
  suspendUser, unsuspendUser, getSuspendedUsers,
  overrideThreatLevel, getThreatOverride, userOverrideThreatLevel,
  blockEmail, unblockEmail, getBlockedEmails, isEmailBlocked,
};
