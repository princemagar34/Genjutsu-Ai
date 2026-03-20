// ============================================================
// admin/adminRoutes.js — Full RBAC with all features
//
// PERMISSIONS:
//   viewer     → stats, users, threats, honeypot, export, settings
//   moderator  → viewer + mark reviewed, notes, dismiss alerts,
//                activity log
//   superadmin → moderator + manage admins, ML thresholds,
//                admin activity log, suspend users, override threats
// ============================================================
const express = require('express');
const {
  getAllUsers, getAllThreats, getSystemStats,
  getAdminByEmail, getAllAdmins, createAdmin,
  updateAdminRole, updateAdminLastLogin, deleteAdmin, toggleAdminStatus,
  addThreatReview, getThreatReview, getAllReviews,
  logActivity, getActivityLog, getAdminActivityLog,
  getSystemSetting, getAllSystemSettings, updateSystemSetting,
  suspendUser, unsuspendUser, getSuspendedUsers,
  overrideThreatLevel, getThreatOverride,
  markAllAlertsRead, getAlerts,
  getAllHoneypotSessions, endHoneypotSession,
  updateHoneypotSession, getHoneypotSessionById
} = require('../database/db');

const router = express.Router();

// ── Permission map ────────────────────────────────────────────
const PERMISSIONS = {
  superadmin: [
    'stats','users','threats','honeypot','export','settings',
    'review','notes','dismiss','activity',
    'admins','ml_settings','admin_activity','suspend_user','override_threat'
  ],
  moderator: [
    'stats','users','threats','honeypot','export','settings',
    'review','notes','dismiss','activity'
  ],
  viewer: [
    'stats','users','threats','honeypot','export','settings'
  ]
};

const ROLE_LABELS = {
  superadmin: 'Super Admin',
  moderator:  'Moderator',
  viewer:     'Viewer'
};

// ── Helpers ───────────────────────────────────────────────────
function getIP(req) {
  return req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '';
}

function requireAdmin(req, res, next) {
  if (req.session?.admin?.loggedIn) return next();
  res.status(403).json({ success: false, error: 'Admin access required.' });
}

function can(permission) {
  return (req, res, next) => {
    const role  = req.session?.admin?.role || 'viewer';
    const perms = PERMISSIONS[role] || [];
    if (perms.includes(permission)) return next();
    res.status(403).json({
      success:  false,
      error:    `Your role (${ROLE_LABELS[role]}) cannot perform this action.`,
      role,
      required: permission
    });
  };
}

// ── POST /admin/api/login ─────────────────────────────────────
router.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ success: false, error: 'Email and password required.' });

  const admin = getAdminByEmail(email);
  if (!admin || admin.password !== password)
    return res.status(401).json({ success: false, error: 'Invalid credentials.' });
  if (!admin.is_active)
    return res.status(403).json({ success: false, error: 'This account has been deactivated.' });

  updateAdminLastLogin(email);
  logActivity(email, admin.role, 'LOGIN', 'Admin logged in', getIP(req));

  req.session.admin = {
    loggedIn:     true,
    adminId:      admin.admin_id,
    email:        admin.email,
    name:         admin.name || admin.email,
    role:         admin.role,
    roleLabel:    ROLE_LABELS[admin.role] || admin.role,
    permissions:  PERMISSIONS[admin.role] || [],
    isSuperAdmin: admin.role === 'superadmin'
  };

  res.json({ success: true, admin: req.session.admin });
});

// ── POST /admin/api/logout ────────────────────────────────────
router.post('/logout', requireAdmin, (req, res) => {
  logActivity(req.session.admin.email, req.session.admin.role, 'LOGOUT', 'Admin logged out', getIP(req));
  req.session.admin = null;
  res.json({ success: true });
});

// ── GET /admin/api/me ─────────────────────────────────────────
router.get('/me', (req, res) => {
  if (req.session?.admin?.loggedIn)
    return res.json({ loggedIn: true, admin: req.session.admin });
  res.json({ loggedIn: false });
});

// ── GET /admin/api/stats ──────────────────────────────────────
router.get('/stats', requireAdmin, can('stats'), (req, res) => {
  try { res.json({ success: true, stats: getSystemStats() }); }
  catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── GET /admin/api/users ──────────────────────────────────────
router.get('/users', requireAdmin, can('users'), (req, res) => {
  try {
    const users    = getAllUsers();
    const suspended = getSuspendedUsers().map(s => s.user_id);
    const result   = users.map(u => ({
      ...u,
      is_suspended: suspended.includes(u.user_id)
    }));
    res.json({ success: true, users: result });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── POST /admin/api/users/:id/suspend ─── superadmin only ─────
router.post('/users/:id/suspend', requireAdmin, can('suspend_user'), (req, res) => {
  const { email, reason } = req.body;
  if (!email) return res.status(400).json({ success: false, error: 'Email required.' });
  try {
    suspendUser(req.params.id, email, reason, req.session.admin.email);
    logActivity(req.session.admin.email, req.session.admin.role,
      'ADMIN_SUSPEND_USER', `Suspended user: ${email} — reason: ${reason}`, getIP(req));
    res.json({ success: true, message: `User ${email} has been suspended.` });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── POST /admin/api/users/:id/unsuspend ──────────────────────
router.post('/users/:id/unsuspend', requireAdmin, can('suspend_user'), (req, res) => {
  const { email } = req.body;
  try {
    unsuspendUser(req.params.id);
    logActivity(req.session.admin.email, req.session.admin.role,
      'ADMIN_UNSUSPEND_USER', `Unsuspended user: ${email}`, getIP(req));
    res.json({ success: true, message: 'User unsuspended.' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── GET /admin/api/threats ────────────────────────────────────
router.get('/threats', requireAdmin, can('threats'), (req, res) => {
  try {
    const limit   = parseInt(req.query.limit) || 200;
    const threats = getAllThreats(limit);
    const reviews = getAllReviews();
    const reviewMap = {};
    reviews.forEach(r => { reviewMap[r.email_id] = r; });

    const result = threats.map(t => ({
      ...t,
      review: reviewMap[t.email_id] || null
    }));
    res.json({ success: true, threats: result });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── POST /admin/api/threats/:id/review ── moderator+ ──────────
router.post('/threats/:id/review', requireAdmin, can('review'), (req, res) => {
  const { note, status } = req.body;
  try {
    addThreatReview(req.params.id, req.session.admin.email, note, status || 'reviewed');
    logActivity(req.session.admin.email, req.session.admin.role,
      'THREAT_REVIEWED', `Reviewed threat ${req.params.id}: ${note||'no note'}`, getIP(req));
    res.json({ success: true, message: 'Threat marked as reviewed.' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── POST /admin/api/threats/:id/override ── superadmin only ───
router.post('/threats/:id/override', requireAdmin, can('override_threat'), (req, res) => {
  const { originalLevel, newLevel, note } = req.body;
  if (!newLevel) return res.status(400).json({ success: false, error: 'newLevel required.' });
  if (!['safe','suspicious','dangerous'].includes(newLevel))
    return res.status(400).json({ success: false, error: 'newLevel must be safe, suspicious, or dangerous.' });
  try {
    overrideThreatLevel(req.params.id, originalLevel, newLevel, req.session.admin.email, note);
    logActivity(req.session.admin.email, req.session.admin.role,
      'ADMIN_THREAT_OVERRIDE',
      `Override threat ${req.params.id}: ${originalLevel} → ${newLevel}. Note: ${note||'none'}`,
      getIP(req));
    res.json({ success: true, message: `Threat level overridden to ${newLevel}.` });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── GET /admin/api/activity ── moderator+ ─────────────────────
router.get('/activity', requireAdmin, can('activity'), (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    res.json({ success: true, logs: getActivityLog(limit) });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── GET /admin/api/admin-activity ── superadmin only ──────────
router.get('/admin-activity', requireAdmin, can('admin_activity'), (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    res.json({ success: true, logs: getAdminActivityLog(limit) });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── GET /admin/api/settings ── all roles ──────────────────────
router.get('/settings', requireAdmin, can('settings'), (req, res) => {
  try {
    const rows = getAllSystemSettings();
    const settings = {};
    rows.forEach(r => { settings[r.key] = r.value; });
    res.json({ success: true, settings });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── PUT /admin/api/settings ── all roles ──────────────────────
router.put('/settings', requireAdmin, can('settings'), (req, res) => {
  const { key, value } = req.body;
  if (!key || value === undefined)
    return res.status(400).json({ success: false, error: 'key and value required.' });

  // Only superadmin can change ML thresholds
  const mlKeys = ['threat_score_dangerous','threat_score_suspicious'];
  if (mlKeys.includes(key) && req.session.admin.role !== 'superadmin') {
    return res.status(403).json({
      success: false,
      error:   'Only Super Admin can change ML threat score thresholds.'
    });
  }

  try {
    updateSystemSetting(key, String(value), req.session.admin.email);
    logActivity(req.session.admin.email, req.session.admin.role,
      'SETTINGS_CHANGED', `Setting "${key}" changed to "${value}"`, getIP(req));
    res.json({ success: true, message: `Setting updated: ${key} = ${value}` });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── GET /admin/api/admins ── superadmin only ──────────────────
router.get('/admins', requireAdmin, can('admins'), (req, res) => {
  try {
    const admins = getAllAdmins().map(({ password, ...rest }) => rest);
    res.json({ success: true, admins });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── POST /admin/api/admins ── superadmin only ─────────────────
router.post('/admins', requireAdmin, can('admins'), (req, res) => {
  const { email, password, role, name } = req.body;
  if (!email || !password)
    return res.status(400).json({ success: false, error: 'Email and password required.' });
  if (!['viewer','moderator'].includes(role))
    return res.status(400).json({ success: false, error: 'Role must be viewer or moderator.' });
  if (getAdminByEmail(email))
    return res.status(409).json({ success: false, error: 'Admin with this email already exists.' });

  try {
    const id = createAdmin({
      email, password, role,
      name:      name || email.split('@')[0],
      createdBy: req.session.admin.email
    });
    logActivity(req.session.admin.email, req.session.admin.role,
      'ADMIN_CREATED', `Created admin: ${email} with role ${role}`, getIP(req));
    res.json({ success: true, adminId: id });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── PUT /admin/api/admins/:id/role ── superadmin only ─────────
router.put('/admins/:id/role', requireAdmin, can('admins'), (req, res) => {
  const { role } = req.body;
  if (!['viewer','moderator'].includes(role))
    return res.status(400).json({ success: false, error: 'Can only assign viewer or moderator.' });

  const target = getAllAdmins().find(a => a.admin_id === req.params.id);
  if (!target)    return res.status(404).json({ success: false, error: 'Admin not found.' });
  if (target.role === 'superadmin')
    return res.status(403).json({ success: false, error: 'Cannot change Super Admin role.' });

  try {
    updateAdminRole(req.params.id, role);
    logActivity(req.session.admin.email, req.session.admin.role,
      'ADMIN_ROLE_CHANGED', `Changed ${target.email} role to ${role}`, getIP(req));
    res.json({ success: true, message: `Role updated to ${ROLE_LABELS[role]}` });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── PUT /admin/api/admins/:id/toggle ── superadmin only ───────
router.put('/admins/:id/toggle', requireAdmin, can('admins'), (req, res) => {
  const target = getAllAdmins().find(a => a.admin_id === req.params.id);
  if (!target)    return res.status(404).json({ success: false, error: 'Admin not found.' });
  if (target.role === 'superadmin')
    return res.status(403).json({ success: false, error: 'Cannot deactivate Super Admin.' });

  try {
    toggleAdminStatus(req.params.id);
    logActivity(req.session.admin.email, req.session.admin.role,
      'ADMIN_TOGGLED', `Toggled admin status: ${target.email}`, getIP(req));
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── DELETE /admin/api/admins/:id ── superadmin only ───────────
router.delete('/admins/:id', requireAdmin, can('admins'), (req, res) => {
  const target = getAllAdmins().find(a => a.admin_id === req.params.id);
  if (!target)    return res.status(404).json({ success: false, error: 'Admin not found.' });
  if (target.role === 'superadmin')
    return res.status(403).json({ success: false, error: 'Cannot delete Super Admin.' });

  try {
    deleteAdmin(req.params.id);
    logActivity(req.session.admin.email, req.session.admin.role,
      'ADMIN_DELETED', `Deleted admin: ${target.email}`, getIP(req));
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── GET /admin/api/honeypot/sessions ── viewer+ ───────────────
// Returns all honeypot sessions across ALL users for admin oversight
router.get('/honeypot/sessions', requireAdmin, can('honeypot'), (req, res) => {
  try {
    const sessions = getAllHoneypotSessions();
    const now = Date.now();

    const enriched = sessions.map(s => {
      const startedAt     = s.started_at ? new Date(s.started_at).getTime() : now;
      const minutesWasted = s.status === 'active'
        ? Math.floor((now - startedAt) / 60000)
        : (s.minutes_wasted || 0);
      return {
        sessionId:    s.session_id,
        userId:       s.user_id,
        userEmail:    s.user_email  || null,
        userName:     s.user_name   || null,
        emailId:      s.email_id,
        threadId:     s.thread_id,
        senderEmail:  s.sender_email,
        subject:      s.subject,
        repliesSent:  s.replies_sent   || 0,
        minutesWasted,
        startedAt:    s.started_at,
        lastReplyAt:  s.last_reply_at,
        status:       s.status || 'active'
      };
    });

    const stats = {
      total:           enriched.length,
      active:          enriched.filter(s => s.status === 'active').length,
      ended:           enriched.filter(s => s.status === 'ended').length,
      totalReplies:    enriched.reduce((a, s) => a + s.repliesSent, 0),
      totalMinutes:    enriched.reduce((a, s) => a + s.minutesWasted, 0),
      uniqueAttackers: new Set(enriched.map(s => s.senderEmail).filter(Boolean)).size
    };

    res.json({ success: true, stats, sessions: enriched });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── DELETE /admin/api/honeypot/sessions/:sessionId ── moderator+ ──
router.delete('/honeypot/sessions/:sessionId', requireAdmin, can('review'), (req, res) => {
  try {
    const session = getHoneypotSessionById(req.params.sessionId);
    if (session && session.started_at) {
      const elapsed = Math.floor((Date.now() - new Date(session.started_at).getTime()) / 60000);
      updateHoneypotSession(req.params.sessionId, {
        minutes_wasted: elapsed,
        status: 'ended'
      });
    }
    endHoneypotSession(req.params.sessionId);
    logActivity(
      req.session.admin.email, req.session.admin.role,
      'HONEYPOT_TERMINATED', `Terminated honeypot session: ${req.params.sessionId}`, getIP(req)
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
