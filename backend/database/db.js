// ============================================================
// database/db.js — PostgreSQL Database (migrated from SQLite)
// ============================================================
const { Pool } = require('pg');
const { sealColumn, isSealed } = require('../services/mail/tokens');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Cloud SQL via Unix socket does not use SSL. Hosted databases such as Neon
  // put ?sslmode=require in DATABASE_URL, and then SSL is switched on.
  ssl: /sslmode=(require|verify-ca|verify-full)/.test(process.env.DATABASE_URL || '') ? { rejectUnauthorized: true } : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 20000,      // Neon free tier sleeps when idle; waking it can take several seconds
  keepAlive: true,                    // stop idle connections being silently cut
});

// Hosted databases such as Neon close idle connections (and suspend the
// database when unused). pg reports that as an 'error' event on the pool;
// with no listener Node treats it as fatal and the whole server stops.
// Log it instead — the pool opens a fresh connection for the next query.
pool.on('error', (err) => {
  console.warn('⚠️  Database connection dropped (reconnecting automatically):', err.message);
});

// The pool's listener only covers connections sitting idle. A connection that is
// checked out (in the middle of a query) emits 'error' on itself when Neon cuts it,
// and with no listener there Node crashes. Give every connection its own listener;
// the query itself then fails, query() below retries once on a fresh connection.
pool.on('connect', (client) => {
  client.on('error', (err) => {
    console.warn('⚠️  Database connection dropped mid-use (will reconnect):', err.message);
  });
});

// Errors that mean "this connection died", not "this query is wrong"
function isConnectionLost(err) {
  return ['ECONNRESET', 'EPIPE', 'ETIMEDOUT', '57P01', '57P02', '57P03'].includes(err.code)
      || /Connection terminated|connection is closed|Client has encountered a connection error/i.test(err.message || '');
}

// ── Helper: run a query (retries once on a dropped connection) ─
async function query(text, params, attempt = 1) {
  let client;
  try {
    client = await pool.connect();
  } catch (err) {
    // Could not even open a connection (database waking up, or a network blip): wait and try once more
    if (attempt === 1 && (isConnectionLost(err) || /timeout/i.test(err.message || ''))) {
      console.warn('⚠️  Database slow to connect, retrying…');
      await new Promise(r => setTimeout(r, 1500));
      return query(text, params, 2);
    }
    throw err;
  }
  let result, failure;
  try {
    result = await client.query(text, params);
  } catch (err) {
    failure = err;
  }
  const lost = failure && isConnectionLost(failure);
  client.release(lost ? failure : undefined);   // a dead connection is discarded, not reused
  if (!failure) return result;
  if (lost && attempt === 1) return query(text, params, 2);   // try once more on a fresh one
  throw failure;
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

    CREATE TABLE IF NOT EXISTS user_rules (
      rule_id    TEXT PRIMARY KEY,
      user_id    TEXT NOT NULL,
      field      TEXT NOT NULL,      -- sender | domain | subject | attachment
      value      TEXT NOT NULL,
      action     TEXT NOT NULL,      -- trust | flag | quarantine
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS user_activity (
      activity_id TEXT PRIMARY KEY,
      user_id     TEXT NOT NULL,
      action      TEXT NOT NULL,
      detail      TEXT,
      at          TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_user_activity_user ON user_activity (user_id, at DESC);

    CREATE TABLE IF NOT EXISTS user_api_keys (
      key_id     TEXT PRIMARY KEY,
      user_id    TEXT NOT NULL,
      name       TEXT NOT NULL,
      prefix     TEXT NOT NULL,
      key_hash   TEXT UNIQUE NOT NULL,   -- SHA-256 of the key; the key itself is shown once and never stored
      created_at TIMESTAMPTZ DEFAULT NOW(),
      last_used  TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS user_safe_senders (
      user_id      TEXT NOT NULL,
      sender_email TEXT NOT NULL,
      added_at     TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (user_id, sender_email)
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

    -- Multi-provider sign-in (Gmail / Outlook / IMAP). Existing rows are Google users.
    ALTER TABLE users ADD COLUMN IF NOT EXISTS provider         TEXT DEFAULT 'google';
    ALTER TABLE user_settings  ADD COLUMN IF NOT EXISTS weekly_digest   INTEGER DEFAULT 0;
    ALTER TABLE user_settings  ADD COLUMN IF NOT EXISTS last_digest_at  TIMESTAMPTZ;
    ALTER TABLE user_settings  ADD COLUMN IF NOT EXISTS discord_webhook TEXT;
    ALTER TABLE blocked_emails ADD COLUMN IF NOT EXISTS reason          TEXT DEFAULT 'manual';
    ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS mitre    TEXT;
    ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS iocs     TEXT;
    ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS category TEXT;
    ALTER TABLE honeypot_sessions ADD COLUMN IF NOT EXISTS persona     TEXT DEFAULT 'teacher';
    ALTER TABLE honeypot_sessions ADD COLUMN IF NOT EXISTS stop_reason TEXT;
    ALTER TABLE user_settings     ADD COLUMN IF NOT EXISTS honeypot_persona TEXT DEFAULT 'teacher';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS mail_provider    TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS mail_credentials TEXT;  -- AES-256-GCM sealed, IMAP only
    CREATE TABLE IF NOT EXISTS global_blocklist (
      domain     TEXT PRIMARY KEY,
      reason     TEXT,
      added_by   TEXT,
      added_at   TIMESTAMPTZ DEFAULT NOW()
    );
    ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS origin_ip      TEXT;
    ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS origin_country TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS last_scan_at       TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS last_scan_error    TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS last_scan_error_at TIMESTAMPTZ;
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
    ['max_emails_scan',         '100'],
    ['honeypot_enabled',        'true'],
    ['team_alerts',             'true'],
    ['scan_on_login',           'true'],
  ];
  for (const [k, v] of defaults) {
    await query(
      `INSERT INTO system_settings (key, value, updated_by)
       VALUES ($1, $2, 'system') ON CONFLICT (key) DO NOTHING`,
      [k, v]
    );
  }

  // One-time upgrade: the inbox now checks the latest 100 emails. Moves the old
  // default (50) up once; a value an admin chose later is left alone.
  await query(`
    WITH done AS (
      INSERT INTO system_settings (key, value, updated_by)
      VALUES ('upgrade_scan_100', 'done', 'system') ON CONFLICT (key) DO NOTHING RETURNING key
    )
    UPDATE system_settings SET value = '100'
    WHERE key = 'max_emails_scan' AND value = '50' AND EXISTS (SELECT 1 FROM done)
  `);

  // Seed super admin from .env
  await seedSuperAdmin();

  console.log('✅ PostgreSQL tables ready');
}

async function seedSuperAdmin() {
  const email    = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;
  if (!email || !password) return;

  const { hashPassword } = require('../admin/adminAuth');
  await query(`
    INSERT INTO admin_users (admin_id, email, password, role, name, created_by)
    VALUES ('superadmin-1', $1, $2, 'superadmin', 'Super Admin', 'system')
    ON CONFLICT (email) DO UPDATE SET role = 'superadmin'
  `, [email, hashPassword(password)]);   // stored as a hash; existing rows keep their own (already hashed) password
  console.log(`✅ Super admin ready: ${email}`);
}

// ── User helpers ─────────────────────────────────────────────

// One-off on startup: encrypt any tokens saved before encryption existed
async function encryptStoredTokens() {
  const { rows } = await query(`SELECT user_id, gmail_token, refresh_token FROM users
                                WHERE (gmail_token IS NOT NULL AND gmail_token NOT LIKE 'v1:%')
                                   OR (refresh_token IS NOT NULL AND refresh_token NOT LIKE 'v1:%')`);
  for (const r of rows) {
    await query('UPDATE users SET gmail_token = $2, refresh_token = $3 WHERE user_id = $1',
      [r.user_id, sealColumn(r.gmail_token), sealColumn(r.refresh_token)]);
  }
  if (rows.length) console.log(`🔐 Encrypted stored tokens for ${rows.length} user(s)`);
}

// ── Trusted senders ("Mark safe" teaches Genjutsu) ───────────
const plainAddr = v => ((String(v || '').match(/<([^>]+)>/) || String(v || '').match(/([^\s<>"]+@[^\s<>"]+)/) || [])[1] || '').trim().toLowerCase();

async function getSafeSenders(userId) {
  const { rows } = await query('SELECT sender_email, added_at FROM user_safe_senders WHERE user_id=$1 ORDER BY added_at DESC', [userId]);
  return rows;
}
async function addSafeSender(userId, sender) {
  const addr = plainAddr(sender) || String(sender || '').trim().toLowerCase();
  if (!addr || !addr.includes('@')) return null;
  await query('INSERT INTO user_safe_senders (user_id, sender_email) VALUES ($1,$2) ON CONFLICT DO NOTHING', [userId, addr]);
  return addr;
}
async function removeSafeSender(userId, sender) {
  const addr = plainAddr(sender) || String(sender || '').trim().toLowerCase();
  await query('DELETE FROM user_safe_senders WHERE user_id=$1 AND sender_email=$2', [userId, addr]);
  return addr;
}

// Context for a scan: the user's trusted senders + how many safe emails
// each sender has sent before. One query each, whatever the inbox size.
// ── Global block list (admins) — cached for a minute ─────────
let _blockCache = { at: 0, set: new Set() };
async function getGlobalBlockSet() {
  if (Date.now() - _blockCache.at < 60000) return _blockCache.set;
  try {
    const { rows } = await query('SELECT domain FROM global_blocklist');
    _blockCache = { at: Date.now(), set: new Set(rows.map(r => r.domain)) };
  } catch (_) { _blockCache.at = Date.now(); }
  return _blockCache.set;
}
function clearGlobalBlockCache() { _blockCache.at = 0; }

// Remember whether this user's last scan worked, so admins can spot broken connections
async function markScan(userId, error) {
  if (!userId) return;
  try {
    if (error) await query('UPDATE users SET last_scan_error=$2, last_scan_error_at=NOW() WHERE user_id=$1', [userId, String(error).slice(0, 300)]);
    else await query('UPDATE users SET last_scan_at=NOW(), last_scan_error=NULL WHERE user_id=$1', [userId]);
  } catch (_) { /* never block a scan on this */ }
}

async function getScanContext(userId) {
  const ctx = { safeSenders: new Set(), history: {} };
  ctx.blockedDomains = await getGlobalBlockSet();
  try { ctx.shared = await require('../services/sharedFeed').getActive(); } catch (_) {}
  if (!userId) return ctx;
  if (String(userId).startsWith('demo-')) ctx.domainAge = false;   // demo: no outside lookups
  try {
    const [safe, hist, rules, seen] = await Promise.all([
      query('SELECT sender_email FROM user_safe_senders WHERE user_id=$1', [userId]),
      query('SELECT rule_id, field, value, action FROM user_rules WHERE user_id=$1', [userId]),
      query(`SELECT sender_email, COUNT(*)::int AS n FROM emails
             WHERE user_id=$1 AND is_phishing=0 GROUP BY sender_email`, [userId]),
      // every earlier email from each sender, for "first time this sender emailed you"
      query(`SELECT sender_email, COUNT(DISTINCT gmail_message_id)::int AS n,
                    (array_agg(DISTINCT gmail_message_id))[1:6] AS ids, MIN(scanned_at) AS first
             FROM emails WHERE user_id=$1 GROUP BY sender_email`, [userId])
    ]);
    safe.rows.forEach(r => ctx.safeSenders.add(r.sender_email));
    ctx.rules = rules.rows;
    hist.rows.forEach(r => { const a = plainAddr(r.sender_email); if (a) ctx.history[a] = (ctx.history[a] || 0) + r.n; });
    ctx.seen = {};
    seen.rows.forEach(r => { const a = plainAddr(r.sender_email); if (!a) return;
      const cur = ctx.seen[a] || { n: 0, ids: [], first: r.first };
      cur.n += r.n; cur.ids.push(...(r.ids || [])); if (r.first < cur.first) cur.first = r.first;
      ctx.seen[a] = cur; });
  } catch (_) { /* scanning still works without context */ }
  return ctx;
}

async function getEmailSender(dbEmailId) {
  const { rows } = await query('SELECT sender_email FROM emails WHERE email_id=$1', [dbEmailId]);
  return rows[0]?.sender_email || null;
}

// ── Rules ────────────────────────────────────────────────────
async function getRules(userId) {
  return (await query('SELECT * FROM user_rules WHERE user_id=$1 ORDER BY created_at', [userId])).rows;
}
async function addRule(userId, { field, value, action }) {
  const id = `rule-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
  await query('INSERT INTO user_rules (rule_id, user_id, field, value, action) VALUES ($1,$2,$3,$4,$5)',
    [id, userId, field, String(value).trim().toLowerCase(), action]);
  return id;
}
async function deleteRule(userId, ruleId) {
  await query('DELETE FROM user_rules WHERE user_id=$1 AND rule_id=$2', [userId, ruleId]);
}

// ── User activity log ────────────────────────────────────────
async function logUserActivity(userId, action, detail = '') {
  if (!userId) return;
  try {
    await query('INSERT INTO user_activity (activity_id, user_id, action, detail) VALUES ($1,$2,$3,$4)',
      [`act-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`, userId, action, String(detail).slice(0, 300)]);
  } catch (_) { /* logging never breaks the action itself */ }
}
async function getUserActivity(userId, limit = 50) {
  return (await query('SELECT action, detail, at FROM user_activity WHERE user_id=$1 ORDER BY at DESC LIMIT $2', [userId, limit])).rows;
}

// ── Discord webhook (stored encrypted) ───────────────────────
async function setDiscordWebhook(userId, sealedUrl) {
  await query('INSERT INTO user_settings (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING', [userId]);
  await query('UPDATE user_settings SET discord_webhook=$2, updated_at=NOW() WHERE user_id=$1', [userId, sealedUrl]);
}

// ── Weekly digest ────────────────────────────────────────────
async function getDigestData(userId, days = 7) {
  const since = Date.now() - days * 86400000;
  const rows = (await query(`SELECT sender_email, subject, received_date, confidence_score, is_phishing
                             FROM emails WHERE user_id=$1 AND scanned_at >= NOW() - INTERVAL '30 days'`, [userId])).rows
    .filter(r => { const t = new Date(r.received_date).getTime(); return !isNaN(t) && t >= since; });
  const dangerous = rows.filter(r => r.confidence_score >= 0.6);
  const suspicious = rows.filter(r => r.confidence_score >= 0.3 && r.confidence_score < 0.6);
  const quarantined = (await query(`SELECT COUNT(*)::int n FROM blocked_emails WHERE user_id=$1 AND blocked_at >= NOW() - INTERVAL '7 days'`, [userId])).rows[0].n;
  const hp = (await query(`SELECT COALESCE(SUM(minutes_wasted),0)::int mins, COUNT(*)::int n FROM honeypot_sessions WHERE user_id=$1 AND started_at >= NOW() - INTERVAL '7 days'`, [userId])).rows[0];
  const top = [...dangerous, ...suspicious].sort((a, b) => b.confidence_score - a.confidence_score).slice(0, 5);
  return { total: rows.length, dangerous: dangerous.length, suspicious: suspicious.length, quarantined, honeypotSessions: hp.n, honeypotMinutes: hp.mins, top };
}
async function getUsersDueForDigest() {
  return (await query(`SELECT u.user_id FROM users u JOIN user_settings s ON s.user_id = u.user_id
                       WHERE s.weekly_digest = 1 AND COALESCE(u.status,'active') <> 'suspended'
                         AND (s.last_digest_at IS NULL OR s.last_digest_at < NOW() - INTERVAL '7 days')`)).rows.map(r => r.user_id);
}
async function markDigestSent(userId) {
  await query('UPDATE user_settings SET last_digest_at=NOW() WHERE user_id=$1', [userId]);
}
// A user rebuilt from the database (tokens stay sealed) for background jobs
async function getStoredUser(userId) {
  const r = (await query('SELECT user_id, email, username, provider, mail_provider, mail_credentials, gmail_token, refresh_token FROM users WHERE user_id=$1', [userId])).rows[0];
  if (!r) return null;
  const { open } = require('../services/mail/secretBox');
  const { seal } = require('../services/mail/secretBox');
  const opened = v => { try { return v ? open(v) : null; } catch (_) { return null; } };
  const a = opened(r.gmail_token), rt = opened(r.refresh_token);
  return {
    id: r.user_id, email: r.email, name: r.username, provider: r.provider || 'google',
    mailProvider: r.mail_provider || undefined, mailCreds: r.mail_credentials || undefined,
    ...(a || rt ? { tokenBox: seal({ a, r: rt }) } : {})
  };
}
async function saveStoredTokens(userId, user) {
  if (!user || !user.tokenBox) return;
  const { open } = require('../services/mail/secretBox');
  const t = open(user.tokenBox);
  await query('UPDATE users SET gmail_token=$2, refresh_token=$3 WHERE user_id=$1', [userId, sealColumn(t.a), sealColumn(t.r)]);
}

// ── Delete account: everything belonging to the user ─────────
async function deleteUserData(userId) {
  const prefix = `${userId}-%`;
  const steps = [
    ['DELETE FROM honeypot_messages WHERE session_id IN (SELECT session_id FROM honeypot_sessions WHERE user_id=$1)', [userId]],
    ['DELETE FROM honeypot_sessions WHERE user_id=$1', [userId]],
    ['DELETE FROM scan_results WHERE email_id LIKE $1', [prefix]],
    ['DELETE FROM threat_overrides WHERE email_id LIKE $1', [prefix]],
    ['DELETE FROM threat_reviews WHERE email_id LIKE $1', [prefix]],
    ['DELETE FROM remark_notifications WHERE user_id=$1', [userId]],
    ['DELETE FROM alerts WHERE user_id=$1', [userId]],
    ['DELETE FROM blocked_emails WHERE user_id=$1', [userId]],
    ['DELETE FROM emails WHERE user_id=$1', [userId]],
    ['DELETE FROM user_safe_senders WHERE user_id=$1', [userId]],
    ['DELETE FROM user_rules WHERE user_id=$1', [userId]],
    ['DELETE FROM user_api_keys WHERE user_id=$1', [userId]],
    ['DELETE FROM user_activity WHERE user_id=$1', [userId]],
    // Training examples stay so the model keeps learning. They already have names,
    // addresses, links and numbers removed; here the link to the person goes too.
    ["UPDATE training_samples SET user_id=NULL WHERE user_id=$1", [userId]],
    ['DELETE FROM user_settings WHERE user_id=$1', [userId]],
    ["DELETE FROM user_sessions WHERE sess::jsonb #>> '{user,id}' = $1", [userId]],
    ['DELETE FROM users WHERE user_id=$1', [userId]]
  ];
  for (const [sql, params] of steps) {
    try { await query(sql, params); }
    catch (err) { if (!/does not exist/.test(err.message)) throw err; }   // optional tables
  }
}

// ── Sender profile: what this sender has sent before ─────────
async function getSenderProfile(userId, address) {
  const addr = String(address || '').trim().toLowerCase();
  if (!addr.includes('@')) return null;
  const rows = (await query(`
    SELECT DISTINCT ON (gmail_message_id) subject, received_date, is_phishing, confidence_score, scanned_at
    FROM emails WHERE user_id=$1 AND LOWER(sender_email) LIKE $2
    ORDER BY gmail_message_id, scanned_at DESC`, [userId, `%${addr.replace(/[%_]/g, '')}%`])).rows;
  const dated = rows.map(r => ({ ...r, t: new Date(r.received_date).getTime() })).filter(r => !isNaN(r.t)).sort((a, b) => b.t - a.t);
  const trusted = (await query('SELECT 1 FROM user_safe_senders WHERE user_id=$1 AND sender_email=$2', [userId, addr])).rows.length > 0;
  return {
    address: addr,
    total: rows.length,
    flagged: rows.filter(r => r.confidence_score >= 0.3).length,
    safe: rows.filter(r => r.confidence_score < 0.3).length,
    avgScore: rows.length ? Math.round(rows.reduce((a, r) => a + (r.confidence_score || 0), 0) / rows.length * 100) : 0,
    firstSeen: dated.length ? new Date(dated[dated.length - 1].t).toISOString() : null,
    lastSeen: dated.length ? new Date(dated[0].t).toISOString() : null,
    recent: dated.slice(0, 5).map(r => ({ subject: r.subject, date: new Date(r.t).toISOString(), score: Math.round((r.confidence_score || 0) * 100) })),
    trusted
  };
}

// ── Insights: latest scan of each email in the last 30 days ──
async function getInsightRows(userId) {
  return (await query(`
    SELECT DISTINCT ON (e.gmail_message_id) e.sender_email, s.threat_type AS level, s.details, s.mitre, s.iocs
    FROM emails e
    JOIN LATERAL (SELECT threat_type, details, mitre, iocs FROM scan_results WHERE email_id = e.email_id ORDER BY scan_timestamp DESC LIMIT 1) s ON TRUE
    WHERE e.user_id = $1 AND e.scanned_at >= NOW() - INTERVAL '30 days'
    ORDER BY e.gmail_message_id, e.scanned_at DESC`, [userId])).rows;
}
async function getResponseCounts(userId) {
  const one = async (sql) => (await query(sql, [userId])).rows[0].n;
  return {
    quarantined: await one(`SELECT COUNT(*)::int n FROM blocked_emails WHERE user_id=$1 AND reason='auto'`),
    blocked:     await one(`SELECT COUNT(*)::int n FROM blocked_emails WHERE user_id=$1 AND COALESCE(reason,'manual')<>'auto'`),
    reported:    await one(`SELECT COUNT(*)::int n FROM user_activity WHERE user_id=$1 AND action='Reported phishing to APWG'`),
    honeypotMinutes: await one(`SELECT COALESCE(SUM(minutes_wasted),0)::int n FROM honeypot_sessions WHERE user_id=$1`)
  };
}

// Demo accounts are temporary: remove them after a day
async function pruneDemoUsers() {
  const { rows } = await query(`SELECT user_id FROM users WHERE user_id LIKE 'demo-%' AND created_at < NOW() - INTERVAL '1 day'`);
  for (const r of rows) await deleteUserData(r.user_id);
  return rows.length;
}

// ── SIEM rows ────────────────────────────────────────────────
async function getSiemRows(userId, days = 30) {
  const threats = (await query(`
    SELECT DISTINCT ON (e.gmail_message_id) e.gmail_message_id, e.sender_email, e.subject, e.received_date, e.confidence_score, e.scanned_at,
           s.threat_type, s.threat_subtype, s.details, s.mitre, s.iocs
    FROM emails e
    JOIN LATERAL (SELECT threat_type, threat_subtype, details, mitre, iocs FROM scan_results WHERE email_id = e.email_id ORDER BY scan_timestamp DESC LIMIT 1) s ON TRUE
    WHERE e.user_id=$1 AND e.scanned_at >= NOW() - ($2 || ' days')::interval AND s.threat_type <> 'safe'
    ORDER BY e.gmail_message_id, e.scanned_at DESC`, [userId, String(days)])).rows;
  const activity = (await query(`SELECT action, detail, at FROM user_activity WHERE user_id=$1 AND at >= NOW() - ($2 || ' days')::interval ORDER BY at`, [userId, String(days)])).rows;
  return { threats, activity };
}

// ── API keys (hashed) ────────────────────────────────────────
async function createApiKey(userId, name) {
  const crypto = require('crypto');
  const raw = 'gj_' + crypto.randomBytes(24).toString('base64url');
  const id = `key-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
  await query('INSERT INTO user_api_keys (key_id, user_id, name, prefix, key_hash) VALUES ($1,$2,$3,$4,$5)',
    [id, userId, String(name || 'API key').slice(0, 60), raw.slice(0, 10), crypto.createHash('sha256').update(raw).digest('hex')]);
  return { id, key: raw };
}
async function listApiKeys(userId) {
  return (await query('SELECT key_id, name, prefix, created_at, last_used FROM user_api_keys WHERE user_id=$1 ORDER BY created_at DESC', [userId])).rows;
}
async function revokeApiKey(userId, keyId) {
  await query('DELETE FROM user_api_keys WHERE user_id=$1 AND key_id=$2', [userId, keyId]);
}
async function findUserByApiKey(raw) {
  if (!/^gj_[A-Za-z0-9_-]{20,}$/.test(String(raw || ''))) return null;
  const hash = require('crypto').createHash('sha256').update(raw).digest('hex');
  const row = (await query(`SELECT k.key_id, u.user_id, u.email, u.username, u.status FROM user_api_keys k JOIN users u ON u.user_id = k.user_id WHERE k.key_hash=$1`, [hash])).rows[0];
  if (!row || row.status === 'suspended') return null;
  query('UPDATE user_api_keys SET last_used=NOW() WHERE key_id=$1', [row.key_id]).catch(() => {});
  return { id: row.user_id, email: row.email, name: row.username, keyId: row.key_id };
}

async function upsertUser(user) {
  // gmail_token holds the provider access token (Gmail or Outlook); IMAP users have none
  await query(`
    INSERT INTO users (user_id, email, username, gmail_token, refresh_token, picture, last_login,
                       provider, mail_provider, mail_credentials)
    VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7, $8, $9)
    ON CONFLICT (user_id) DO UPDATE SET
      gmail_token      = EXCLUDED.gmail_token,
      refresh_token    = EXCLUDED.refresh_token,
      provider         = EXCLUDED.provider,
      mail_provider    = EXCLUDED.mail_provider,
      mail_credentials = EXCLUDED.mail_credentials,
      last_login       = NOW()
  `, [user.id, user.email, user.name, sealColumn(user.accessToken), sealColumn(user.refreshToken), user.picture || null,
      user.provider || 'google', user.mailProvider || null, user.mailCreds || null]);

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

  const origin = (() => {
    try {
      const geo = require('../services/geo');
      const ip = geo.originIp(email);
      return { ip, country: geo.countryOf(ip)?.code || null };
    } catch (_) { return { ip: null, country: null }; }
  })();

  const suspiciousUrls = (email.links || []).filter(link =>
    /paypa1\.com|g00gle\.com|amaz0n\.com|micros0ft\.com|secure-login\.|account-verify\.|login-confirm\.|verify-account\.|https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}/.test(link)
  );

  await query(`
    INSERT INTO scan_results
      (scan_id, email_id, scanner_type, threat_detected, threat_type, threat_subtype,
       confidence_level, details, url_scan_results, attachment_scan, mitre, iocs, category,
       origin_ip, origin_country)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
    ON CONFLICT (scan_id) DO NOTHING
  `, [
    scanId, emailId, 'multi-layer-nlp',
    threat.level !== 'safe' ? 1 : 0,
    threat.level,
    threat.subType || null,           // ← CHANGE: store sub-type label
    threat.score / 100,
    JSON.stringify(threat.reasons),
    JSON.stringify(suspiciousUrls),
    JSON.stringify(threat.attachmentDetails || []),
    JSON.stringify(threat.mitre || []),
    threat.iocs ? JSON.stringify(threat.iocs) : null,
    threat.category || null,
    origin.ip, origin.country
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
           s.threat_type, s.details, s.mitre, s.iocs,
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
      SELECT threat_type, details, mitre, iocs
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
                   'honeypot_mode','scan_frequency','telegram_enabled','weekly_digest','honeypot_persona'];
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

// Ending a session keeps the time it wasted (it used to reset to 0)
async function endHoneypotSession(sessionId, stopReason = null) {
  await query(`UPDATE honeypot_sessions
               SET status='ended',
                   minutes_wasted = GREATEST(COALESCE(minutes_wasted,0), FLOOR(EXTRACT(EPOCH FROM (NOW() - started_at)) / 60)::int),
                   stop_reason = COALESCE($2, stop_reason)
               WHERE session_id=$1 AND status <> 'ended'`, [sessionId, stopReason]);
}

async function updateHoneypotSession(sessionId, fields = {}) {
  const allowed = ['minutes_wasted','replies_sent','status','last_reply_at',
                   'references_hdr','last_processed_msg_id','persona','stop_reason'];
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

// ── Admin trend data — real per-day counts across ALL users ──
// Used by the admin panel Threat Trend chart instead of fake estimates.
async function getAdminByEmail(email) {
  const res = await query(
    'SELECT * FROM admin_users WHERE email = $1 AND is_active = 1', [email]
  );
  return res.rows[0];
}

async function getAllAdmins() {
  const res = await query(`
    SELECT a.admin_id, a.email, a.role, a.name, a.created_by, a.created_at, a.last_login, a.is_active, a.totp_enabled, a.org_id, o.name AS org_name
    FROM admin_users a LEFT JOIN organisations o ON o.org_id = a.org_id ORDER BY a.created_at ASC
  `);
  return res.rows;
}

async function createAdmin(admin) {
  const id = 'admin-' + Date.now();
  await query(`
    INSERT INTO admin_users (admin_id, email, password, role, name, created_by, org_id)
    VALUES ($1,$2,$3,$4,$5,$6,$7)
  `, [id, admin.email, admin.password, admin.role || 'viewer', admin.name || '', admin.createdBy || 'superadmin', admin.orgId || null]);
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
    'SELECT user_id, email, username, picture, status, created_at, last_login, provider FROM users WHERE email = $1',
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
  // Save what the level really was (not just "user_override"), so admins can review it
  const prev = (await query(`SELECT COALESCE(
      (SELECT new_level FROM threat_overrides WHERE email_id=$1 ORDER BY overridden_at DESC LIMIT 1),
      (SELECT threat_type FROM scan_results WHERE email_id=$1 ORDER BY scan_timestamp DESC LIMIT 1)) AS lvl`, [emailId])).rows[0]?.lvl || 'unknown';

  await query(`
    INSERT INTO threat_overrides
      (override_id, email_id, original_level, new_level, overridden_by, note)
    VALUES ($1,$2,$3,$4,$5,$6)
  `, [id, emailId, prev, newLevel, userEmail, note || '']);

  // Update is_phishing flag
  await query(
    'UPDATE emails SET is_phishing=$1 WHERE email_id=$2',
    [newLevel !== 'safe' ? 1 : 0, emailId]
  );
}

// Every email Genjutsu scanned for this user, newest scan of each, with any override and
// whether it was quarantined. The Threats page reads this instead of re-reading the inbox,
// so quarantined emails (moved to spam) still count.
async function getUserThreatRecords(userId, days = 90) {
  const { rows } = await query(`
    SELECT * FROM (
      SELECT DISTINCT ON (e.gmail_message_id)
             e.email_id, e.gmail_message_id, e.sender_email, e.subject, e.body_text, e.received_date, e.scanned_at,
             e.confidence_score, e.auth_raw, e.has_attachment,
             sr.threat_type, sr.threat_subtype, sr.details, sr.mitre, sr.iocs, sr.category, sr.attachment_scan, sr.origin_country,
             ov.new_level AS override_level, ov.note AS override_note, ov.overridden_by, ov.overridden_at,
             be.reason AS blocked_reason
      FROM emails e
      LEFT JOIN LATERAL (SELECT * FROM scan_results WHERE email_id = e.email_id ORDER BY scan_timestamp DESC LIMIT 1) sr ON TRUE
      LEFT JOIN LATERAL (SELECT * FROM threat_overrides WHERE email_id = e.email_id ORDER BY overridden_at DESC LIMIT 1) ov ON TRUE
      LEFT JOIN blocked_emails be ON be.email_id = e.email_id AND be.user_id = e.user_id
      WHERE e.user_id = $1 AND e.gmail_message_id IS NOT NULL AND e.scanned_at > NOW() - ($2 || ' days')::interval
      ORDER BY e.gmail_message_id, e.scanned_at DESC
    ) x ORDER BY x.scanned_at DESC`, [userId, String(days)]);
  return rows;
}
const countUserScans = async (userId) => (await query('SELECT COUNT(*)::int AS n FROM emails WHERE user_id=$1', [userId])).rows[0].n;

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

async function blockEmail(userId, emailId, gmailMsgId, senderEmail, subject, reason = 'manual') {
  const id = `blk-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`;
  await query(`
    INSERT INTO blocked_emails (block_id, user_id, email_id, gmail_msg_id, sender_email, subject, reason)
    VALUES ($1,$2,$3,$4,$5,$6,$7)
    ON CONFLICT (user_id, email_id) DO NOTHING
  `, [id, userId, emailId, gmailMsgId || '', senderEmail || '', subject || '', reason]);
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

module.exports = {
  pool, query, initDB, encryptStoredTokens,
  getGlobalBlockSet, clearGlobalBlockCache, markScan, getUserThreatRecords, countUserScans,
  getSafeSenders, addSafeSender, removeSafeSender, getScanContext, getEmailSender,
  getRules, addRule, deleteRule, logUserActivity, getUserActivity, setDiscordWebhook,
  getDigestData, getUsersDueForDigest, markDigestSent, getStoredUser, saveStoredTokens, deleteUserData,
  getSenderProfile, getInsightRows, getResponseCounts, pruneDemoUsers,
  getSiemRows, createApiKey, listApiKeys, revokeApiKey, findUserByApiKey,
  upsertUser, getUserByEmail, saveEmailScan, getAlerts, markAllAlertsRead,
  getUnreadRemarks, markRemarksRead,
  getScanHistory, getReportData, getSettings, updateSettings,
  saveHoneypotSession, getHoneypotSessions, endHoneypotSession,
  updateHoneypotSession, getHoneypotSessionById, getAllHoneypotSessions,
  saveHoneypotMessage, getHoneypotMessages, getHoneypotMessagesBulk,
  getAdminByEmail, getAllAdmins, createAdmin,
  updateAdminRole, updateAdminLastLogin, deleteAdmin, toggleAdminStatus,
  addThreatReview, logActivity, getActivityLog, getAdminActivityLog,
  getSystemSetting, getAllSystemSettings, updateSystemSetting,
  suspendUser, unsuspendUser, overrideThreatLevel, getThreatOverride, userOverrideThreatLevel,
  blockEmail, unblockEmail, getBlockedEmails,
};
