// ============================================================
// database/db.js — SQLite Database (matches your ERD)
// Tables: users, emails, scan_results, alerts, ml_models,
//         honeypot_sessions, user_settings
// Auto-creates genjutsu.db in the database/ folder
// ============================================================
const Database = require('better-sqlite3');
const path     = require('path');

const DB_PATH = path.join(__dirname, 'genjutsu.db');
const db      = new Database(DB_PATH);

db.pragma('journal_mode = WAL'); // faster writes

// ── Create all tables ────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    user_id       TEXT PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    username      TEXT,
    gmail_token   TEXT,
    refresh_token TEXT,
    picture       TEXT,
    created_at    TEXT DEFAULT (datetime('now')),
    last_login    TEXT,
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
    scanned_at       TEXT,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
  );

  CREATE TABLE IF NOT EXISTS scan_results (
    scan_id          TEXT PRIMARY KEY,
    email_id         TEXT NOT NULL,
    scan_timestamp   TEXT DEFAULT (datetime('now')),
    scanner_type     TEXT,
    threat_detected  INTEGER DEFAULT 0,
    threat_type      TEXT,
    confidence_level REAL DEFAULT 0,
    details          TEXT,
    FOREIGN KEY (email_id) REFERENCES emails(email_id)
  );

  CREATE TABLE IF NOT EXISTS alerts (
    alert_id   TEXT PRIMARY KEY,
    email_id   TEXT,
    user_id    TEXT,
    alert_type TEXT,
    message    TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    is_read    INTEGER DEFAULT 0,
    FOREIGN KEY (email_id) REFERENCES emails(email_id),
    FOREIGN KEY (user_id)  REFERENCES users(user_id)
  );

  CREATE TABLE IF NOT EXISTS ml_models (
    model_id   TEXT PRIMARY KEY,
    model_name TEXT,
    version    TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    accuracy   REAL,
    is_active  INTEGER DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS honeypot_sessions (
    session_id     TEXT PRIMARY KEY,
    user_id        TEXT,
    email_id       TEXT,
    sender_email   TEXT,
    subject        TEXT,
    started_at     TEXT DEFAULT (datetime('now')),
    replies_sent   INTEGER DEFAULT 0,
    minutes_wasted INTEGER DEFAULT 0,
    status         TEXT DEFAULT 'active',
    FOREIGN KEY (user_id) REFERENCES users(user_id)
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
    updated_at           TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
  );
`);

// Seed default ML model record
if (!db.prepare('SELECT model_id FROM ml_models WHERE model_id = ?').get('model-v1')) {
  db.prepare(`
    INSERT INTO ml_models (model_id, model_name, version, accuracy, is_active)
    VALUES (?, ?, ?, ?, ?)
  `).run('model-v1', 'Genjutsu Naive Bayes Classifier', '1.0.0', 0.89, 1);
}

// ── Helpers ──────────────────────────────────────────────────

function upsertUser(user) {
  db.prepare(`
    INSERT INTO users (user_id, email, username, gmail_token, refresh_token, picture, last_login)
    VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(user_id) DO UPDATE SET
      gmail_token   = excluded.gmail_token,
      refresh_token = excluded.refresh_token,
      last_login    = datetime('now')
  `).run(user.id, user.email, user.name, user.accessToken, user.refreshToken || null, user.picture || null);

  db.prepare('INSERT OR IGNORE INTO user_settings (user_id) VALUES (?)').run(user.id);
}

function saveEmailScan(email, threat, userId) {
  const emailId = `${userId}-${email.id}`;
  const scanId  = `scan-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;
  const alertId = `alert-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;

  db.prepare(`
    INSERT OR REPLACE INTO emails
      (email_id, user_id, gmail_message_id, sender_email, subject, body_text,
       received_date, is_phishing, confidence_score, scanned_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
  `).run(emailId, userId, email.id, email.from, email.subject,
         (email.body || '').substring(0, 1000),
         email.date, threat.level !== 'safe' ? 1 : 0, threat.score / 100);

  db.prepare(`
    INSERT OR REPLACE INTO scan_results
      (scan_id, email_id, scanner_type, threat_detected, threat_type, confidence_level, details)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(scanId, emailId, 'multi-layer-nlp',
         threat.level !== 'safe' ? 1 : 0,
         threat.level, threat.score / 100,
         JSON.stringify(threat.reasons));

  if (threat.level !== 'safe') {
    db.prepare(`
      INSERT OR IGNORE INTO alerts (alert_id, email_id, user_id, alert_type, message)
      VALUES (?, ?, ?, ?, ?)
    `).run(alertId, emailId, userId, threat.level,
           `${threat.level.toUpperCase()}: "${email.subject}" from ${email.from}`);
  }
}

function getAlerts(userId, limit = 20) {
  return db.prepare(`
    SELECT a.*, e.subject, e.sender_email
    FROM alerts a
    LEFT JOIN emails e ON a.email_id = e.email_id
    WHERE a.user_id = ? AND a.is_read = 0
    ORDER BY a.created_at DESC LIMIT ?
  `).all(userId, limit);
}

function markAlertRead(alertId) {
  db.prepare('UPDATE alerts SET is_read = 1 WHERE alert_id = ?').run(alertId);
}

function markAllAlertsRead(userId) {
  db.prepare('UPDATE alerts SET is_read = 1 WHERE user_id = ?').run(userId);
}

function getScanHistory(userId, days = 7) {
  return db.prepare(`
    SELECT date(scanned_at) as scan_date,
           COUNT(*) as total,
           SUM(is_phishing) as threats
    FROM emails
    WHERE user_id = ?
      AND scanned_at >= datetime('now', '-${days} days')
    GROUP BY date(scanned_at)
    ORDER BY scan_date ASC
  `).all(userId);
}

function getReportData(userId) {
  const user     = db.prepare('SELECT * FROM users WHERE user_id = ?').get(userId);
  const emails   = db.prepare(`
    SELECT e.*, s.threat_type, s.confidence_level, s.details
    FROM emails e LEFT JOIN scan_results s ON e.email_id = s.email_id
    WHERE e.user_id = ? ORDER BY e.scanned_at DESC LIMIT 100
  `).all(userId);
  const stats    = db.prepare(`
    SELECT COUNT(*) as total,
           SUM(is_phishing) as threats,
           SUM(CASE WHEN is_phishing=0 THEN 1 ELSE 0 END) as safe
    FROM emails WHERE user_id = ?
  `).get(userId);
  const honeypot = db.prepare(`
    SELECT COUNT(*) as sessions, SUM(minutes_wasted) as minutes
    FROM honeypot_sessions WHERE user_id = ?
  `).get(userId);
  return { user, emails, stats, honeypot };
}

function getSettings(userId) {
  return db.prepare('SELECT * FROM user_settings WHERE user_id = ?').get(userId)
    || { user_id: userId, real_time_alerts: 1, email_notifications: 1,
         sound_alerts: 0, auto_block: 1, multi_layer_scan: 1,
         link_scanning: 1, honeypot_mode: 0, scan_frequency: 'realtime' };
}

function updateSettings(userId, updates) {
  const allowed = ['real_time_alerts','email_notifications','sound_alerts',
                   'auto_block','multi_layer_scan','link_scanning',
                   'honeypot_mode','scan_frequency','telegram_enabled'];
  const filtered = Object.fromEntries(
    Object.entries(updates).filter(([k]) => allowed.includes(k))
  );
  if (!Object.keys(filtered).length) return;
  const fields = Object.keys(filtered).map(k => `${k} = ?`).join(', ');
  db.prepare(`UPDATE user_settings SET ${fields}, updated_at=datetime('now') WHERE user_id=?`)
    .run(...Object.values(filtered), userId);
}

function saveHoneypotSession(session) {
  db.prepare(`
    INSERT OR REPLACE INTO honeypot_sessions
      (session_id, user_id, email_id, sender_email, subject, replies_sent, minutes_wasted, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(session.session_id, session.user_id, session.email_id,
         session.sender_email, session.subject,
         session.replies_sent, session.minutes_wasted, session.status || 'active');
}

function getHoneypotSessions(userId) {
  return db.prepare(`
    SELECT * FROM honeypot_sessions WHERE user_id=? AND status='active'
    ORDER BY started_at DESC
  `).all(userId);
}

function endHoneypotSession(sessionId) {
  db.prepare("UPDATE honeypot_sessions SET status='ended' WHERE session_id=?").run(sessionId);
}

// ── Admin helpers ────────────────────────────────────────────

function getAllUsers() {
  return db.prepare('SELECT user_id, email, username, picture, created_at, last_login, status FROM users ORDER BY created_at DESC').all();
}

function getAllThreats(limit = 100) {
  return db.prepare(`
    SELECT e.email_id, e.sender_email, e.subject, e.received_date,
           e.is_phishing, e.confidence_score, e.scanned_at,
           s.threat_type, s.details, u.email as user_email
    FROM emails e
    LEFT JOIN scan_results s ON e.email_id = s.email_id
    LEFT JOIN users u ON e.user_id = u.user_id
    WHERE e.is_phishing = 1
    ORDER BY e.scanned_at DESC LIMIT ?
  `).all(limit);
}

function getSystemStats() {
  return {
    totalUsers:    db.prepare('SELECT COUNT(*) as c FROM users').get().c,
    totalEmails:   db.prepare('SELECT COUNT(*) as c FROM emails').get().c,
    totalThreats:  db.prepare('SELECT COUNT(*) as c FROM emails WHERE is_phishing=1').get().c,
    totalHoneypot: db.prepare('SELECT COUNT(*) as c FROM honeypot_sessions').get().c,
    totalAlerts:   db.prepare('SELECT COUNT(*) as c FROM alerts').get().c,
    activeModel:   db.prepare('SELECT * FROM ml_models WHERE is_active=1 LIMIT 1').get()
  };
}

module.exports = {
  db, upsertUser, saveEmailScan, getAlerts, markAlertRead, markAllAlertsRead,
  getScanHistory, getReportData, getSettings, updateSettings,
  saveHoneypotSession, getHoneypotSessions, endHoneypotSession,
  getAllUsers, getAllThreats, getSystemStats,
  getAdminByEmail, getAllAdmins, createAdmin,
  updateAdminRole, updateAdminLastLogin, deleteAdmin, toggleAdminStatus,
  addThreatReview, getThreatReview, getAllReviews,
  logActivity, getActivityLog, getAdminActivityLog,
  getSystemSetting, getAllSystemSettings, updateSystemSetting,
  suspendUser, unsuspendUser, getSuspendedUsers,
  overrideThreatLevel, getThreatOverride
};

// ── Admin users table (added for RBAC) ───────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS admin_users (
    admin_id   TEXT PRIMARY KEY,
    email      TEXT UNIQUE NOT NULL,
    password   TEXT NOT NULL,
    role       TEXT DEFAULT 'viewer',
    name       TEXT,
    created_by TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    last_login TEXT,
    is_active  INTEGER DEFAULT 1
  );
`);

// ── Seed super admin from .env on first run ───────────────────
function seedSuperAdmin() {
  const email    = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;
  if (!email || !password) return;

  const exists = db.prepare('SELECT admin_id FROM admin_users WHERE email = ?').get(email);
  if (!exists) {
    db.prepare(`
      INSERT INTO admin_users (admin_id, email, password, role, name, created_by)
      VALUES (?, ?, ?, 'superadmin', 'Super Admin', 'system')
    `).run('superadmin-1', email, password);
    console.log(`✅ Super admin seeded: ${email}`);
  } else {
    // Always keep super admin role even if somehow changed
    db.prepare(`UPDATE admin_users SET role='superadmin' WHERE email=?`).run(email);
  }
}
seedSuperAdmin();

// ── Admin RBAC helpers ────────────────────────────────────────

function getAdminByEmail(email) {
  return db.prepare('SELECT * FROM admin_users WHERE email = ? AND is_active = 1').get(email);
}

function getAllAdmins() {
  return db.prepare(`
    SELECT admin_id, email, role, name, created_by, created_at, last_login, is_active
    FROM admin_users ORDER BY created_at ASC
  `).all();
}

function createAdmin(admin) {
  const id = 'admin-' + Date.now();
  db.prepare(`
    INSERT INTO admin_users (admin_id, email, password, role, name, created_by)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(id, admin.email, admin.password, admin.role || 'viewer', admin.name || '', admin.createdBy || 'superadmin');
  return id;
}

function updateAdminRole(adminId, role) {
  db.prepare('UPDATE admin_users SET role = ? WHERE admin_id = ?').run(role, adminId);
}

function updateAdminLastLogin(email) {
  db.prepare("UPDATE admin_users SET last_login = datetime('now') WHERE email = ?").run(email);
}

function deleteAdmin(adminId) {
  // Cannot delete the super admin (role = superadmin created by system)
  db.prepare("UPDATE admin_users SET is_active = 0 WHERE admin_id = ? AND created_by != 'system'").run(adminId);
}

function toggleAdminStatus(adminId) {
  db.prepare(`
    UPDATE admin_users SET is_active = CASE WHEN is_active=1 THEN 0 ELSE 1 END
    WHERE admin_id = ? AND created_by != 'system'
  `).run(adminId);
}

// ── New tables for advanced features ─────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS threat_reviews (
    review_id   TEXT PRIMARY KEY,
    email_id    TEXT NOT NULL,
    reviewed_by TEXT NOT NULL,
    note        TEXT,
    status      TEXT DEFAULT 'reviewed',
    reviewed_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS activity_log (
    log_id      TEXT PRIMARY KEY,
    admin_email TEXT NOT NULL,
    admin_role  TEXT,
    action      TEXT NOT NULL,
    detail      TEXT,
    ip_address  TEXT,
    logged_at   TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS system_settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_by  TEXT,
    updated_at  TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS suspended_users (
    user_id     TEXT PRIMARY KEY,
    email       TEXT NOT NULL,
    reason      TEXT,
    suspended_by TEXT,
    suspended_at TEXT DEFAULT (datetime('now')),
    is_active   INTEGER DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS threat_overrides (
    override_id  TEXT PRIMARY KEY,
    email_id     TEXT NOT NULL,
    original_level TEXT,
    new_level    TEXT,
    overridden_by TEXT,
    note         TEXT,
    overridden_at TEXT DEFAULT (datetime('now'))
  );
`);

// ── Seed default system settings ─────────────────────────────
const defaultSettings = [
  ['threat_score_dangerous', '60'],
  ['threat_score_suspicious','30'],
  ['max_emails_scan',        '50'],
  ['honeypot_enabled',       'true'],
  ['telegram_alerts',        'true'],
  ['scan_on_login',          'true']
];
const insertSetting = db.prepare(`
  INSERT OR IGNORE INTO system_settings (key, value, updated_by)
  VALUES (?, ?, 'system')
`);
defaultSettings.forEach(([k,v]) => insertSetting.run(k, v));

// ── Threat review helpers ─────────────────────────────────────
function addThreatReview(emailId, adminEmail, note, status='reviewed') {
  const id = `rev-${Date.now()}-${Math.random().toString(36).substr(2,5)}`;
  db.prepare(`
    INSERT OR REPLACE INTO threat_reviews (review_id, email_id, reviewed_by, note, status)
    VALUES (?,?,?,?,?)
  `).run(id, emailId, adminEmail, note||'', status);
}

function getThreatReview(emailId) {
  return db.prepare('SELECT * FROM threat_reviews WHERE email_id=? ORDER BY reviewed_at DESC LIMIT 1').get(emailId);
}

function getAllReviews() {
  return db.prepare(`
    SELECT tr.*, e.subject, e.sender_email, u.email as user_email
    FROM threat_reviews tr
    LEFT JOIN emails e ON tr.email_id = e.email_id
    LEFT JOIN users  u ON e.user_id   = u.user_id
    ORDER BY tr.reviewed_at DESC LIMIT 100
  `).all();
}

// ── Activity log helpers ──────────────────────────────────────
function logActivity(adminEmail, adminRole, action, detail, ip) {
  const id = `log-${Date.now()}-${Math.random().toString(36).substr(2,5)}`;
  db.prepare(`
    INSERT INTO activity_log (log_id, admin_email, admin_role, action, detail, ip_address)
    VALUES (?,?,?,?,?,?)
  `).run(id, adminEmail, adminRole, action, detail||'', ip||'');
}

function getActivityLog(limit=100) {
  return db.prepare(`
    SELECT * FROM activity_log ORDER BY logged_at DESC LIMIT ?
  `).all(limit);
}

function getAdminActivityLog(limit=100) {
  return db.prepare(`
    SELECT * FROM activity_log
    WHERE action LIKE 'ADMIN_%' OR action LIKE 'LOGIN%'
    ORDER BY logged_at DESC LIMIT ?
  `).all(limit);
}

// ── System settings helpers ───────────────────────────────────
function getSystemSetting(key) {
  const row = db.prepare('SELECT value FROM system_settings WHERE key=?').get(key);
  return row ? row.value : null;
}

function getAllSystemSettings() {
  return db.prepare('SELECT * FROM system_settings').all();
}

function updateSystemSetting(key, value, updatedBy) {
  db.prepare(`
    INSERT INTO system_settings (key, value, updated_by, updated_at)
    VALUES (?,?,?,datetime('now'))
    ON CONFLICT(key) DO UPDATE SET
      value      = excluded.value,
      updated_by = excluded.updated_by,
      updated_at = datetime('now')
  `).run(key, value, updatedBy);
}

// ── Suspend user helpers ──────────────────────────────────────
function suspendUser(userId, email, reason, adminEmail) {
  db.prepare(`
    INSERT OR REPLACE INTO suspended_users (user_id, email, reason, suspended_by)
    VALUES (?,?,?,?)
  `).run(userId, email, reason||'', adminEmail);
  db.prepare("UPDATE users SET status='suspended' WHERE user_id=?").run(userId);
}

function unsuspendUser(userId) {
  db.prepare("UPDATE suspended_users SET is_active=0 WHERE user_id=?").run(userId);
  db.prepare("UPDATE users SET status='active' WHERE user_id=?").run(userId);
}

function getSuspendedUsers() {
  return db.prepare('SELECT * FROM suspended_users WHERE is_active=1').all();
}

// ── Threat override helpers ───────────────────────────────────
function overrideThreatLevel(emailId, originalLevel, newLevel, adminEmail, note) {
  const id = `ov-${Date.now()}-${Math.random().toString(36).substr(2,5)}`;
  db.prepare(`
    INSERT INTO threat_overrides
      (override_id, email_id, original_level, new_level, overridden_by, note)
    VALUES (?,?,?,?,?,?)
  `).run(id, emailId, originalLevel, newLevel, adminEmail, note||'');
  db.prepare(`
    UPDATE emails SET is_phishing=? WHERE email_id=?
  `).run(newLevel !== 'safe' ? 1 : 0, emailId);
}

function getThreatOverride(emailId) {
  return db.prepare('SELECT * FROM threat_overrides WHERE email_id=? ORDER BY overridden_at DESC LIMIT 1').get(emailId);
}
