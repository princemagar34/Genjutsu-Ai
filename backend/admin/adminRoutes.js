// admin/adminRoutes.js — Full RBAC async PostgreSQL version
const express = require('express');
const {
  getAllUsers, getAllThreats, getSystemStats, getAdminTrendData,
  getAdminByEmail, getAllAdmins, createAdmin,
  updateAdminRole, updateAdminLastLogin, deleteAdmin, toggleAdminStatus,
  addThreatReview, getThreatReview, getAllReviews,
  logActivity, getActivityLog, getAdminActivityLog,
  getSystemSetting, getAllSystemSettings, updateSystemSetting,
  suspendUser, unsuspendUser, getSuspendedUsers,
  overrideThreatLevel, getThreatOverride,
  markAllAlertsRead, getAlerts,
  getAllHoneypotSessions, endHoneypotSession,
  updateHoneypotSession, getHoneypotSessionById, getHoneypotMessages
} = require('../database/db');

const router = express.Router();

const PERMISSIONS = {
  superadmin: [
    'stats','users','threats','honeypot','export','settings',
    'review','notes','dismiss','activity',
    'admins','ml_settings','admin_activity','suspend_user','override_threat'
  ],
  moderator: [
    'stats','users','threats','honeypot','export','settings',
    'review','notes','dismiss','activity','override_threat'
  ],
  viewer: ['stats','users','threats','honeypot','export','settings']
};

const ROLE_LABELS = { superadmin: 'Super Admin', moderator: 'Moderator', viewer: 'Viewer' };

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
    res.status(403).json({ success: false, error: `Your role (${ROLE_LABELS[role]}) cannot perform this action.`, role, required: permission });
  };
}

// ── POST /admin/api/login ─────────────────────────────────────
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ success: false, error: 'Email and password required.' });
  try {
    const admin = await getAdminByEmail(email);
    if (!admin || admin.password !== password)
      return res.status(401).json({ success: false, error: 'Invalid credentials.' });
    if (!admin.is_active)
      return res.status(403).json({ success: false, error: 'This account has been deactivated.' });

    await updateAdminLastLogin(email);
    await logActivity(email, admin.role, 'LOGIN', 'Admin logged in', getIP(req));

    req.session.admin = {
      loggedIn: true, adminId: admin.admin_id, email: admin.email,
      name: admin.name || admin.email, role: admin.role,
      roleLabel: ROLE_LABELS[admin.role] || admin.role,
      permissions: PERMISSIONS[admin.role] || [],
      isSuperAdmin: admin.role === 'superadmin'
    };
    res.json({ success: true, admin: req.session.admin });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── POST /admin/api/logout ────────────────────────────────────
router.post('/logout', requireAdmin, async (req, res) => {
  await logActivity(req.session.admin.email, req.session.admin.role, 'LOGOUT', 'Admin logged out', getIP(req));
  req.session.admin = null;
  res.json({ success: true });
});

// ── GET /admin/api/me ─────────────────────────────────────────
router.get('/me', (req, res) => {
  if (req.session?.admin?.loggedIn) return res.json({ loggedIn: true, admin: req.session.admin });
  res.json({ loggedIn: false });
});

// ── GET /admin/api/stats ──────────────────────────────────────
router.get('/stats', requireAdmin, can('stats'), async (req, res) => {
  try { res.json({ success: true, stats: await getSystemStats() }); }
  catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── GET /admin/api/trend ──────────────────────────────────────
// Returns real per-day threat/safe counts for the Threat Trend chart.
// Replaces the fake estimate previously calculated in the frontend.
router.get('/trend', requireAdmin, can('stats'), async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 7;
    const trend = await getAdminTrendData(days);
    res.json({ success: true, trend });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── GET /admin/api/users ──────────────────────────────────────
router.get('/users', requireAdmin, can('users'), async (req, res) => {
  try {
    const users     = await getAllUsers();
    const suspended = (await getSuspendedUsers()).map(s => s.user_id);
    res.json({ success: true, users: users.map(u => ({ ...u, is_suspended: suspended.includes(u.user_id) })) });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── POST /admin/api/users/:id/suspend ────────────────────────
router.post('/users/:id/suspend', requireAdmin, can('suspend_user'), async (req, res) => {
  const { email, reason } = req.body;
  if (!email) return res.status(400).json({ success: false, error: 'Email required.' });
  try {
    await suspendUser(req.params.id, email, reason, req.session.admin.email);
    await logActivity(req.session.admin.email, req.session.admin.role, 'ADMIN_SUSPEND_USER', `Suspended user: ${email} — reason: ${reason}`, getIP(req));
    res.json({ success: true, message: `User ${email} has been suspended.` });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── POST /admin/api/users/:id/unsuspend ──────────────────────
router.post('/users/:id/unsuspend', requireAdmin, can('suspend_user'), async (req, res) => {
  const { email } = req.body;
  try {
    await unsuspendUser(req.params.id);
    await logActivity(req.session.admin.email, req.session.admin.role, 'ADMIN_UNSUSPEND_USER', `Unsuspended user: ${email}`, getIP(req));
    res.json({ success: true, message: 'User unsuspended.' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── GET /admin/api/threats ────────────────────────────────────
router.get('/threats', requireAdmin, can('threats'), async (req, res) => {
  try {
    const limit    = parseInt(req.query.limit) || 200;
    const threats  = await getAllThreats(limit);
    const reviews  = await getAllReviews();
    const reviewMap = {};
    reviews.forEach(r => { reviewMap[r.email_id] = r; });
    res.json({ success: true, threats: threats.map(t => ({ ...t, review: reviewMap[t.email_id] || null })) });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── GET /admin/api/blocked ────────────────────────────────────
// Returns all emails flagged as phishing (is_phishing=1),
// enriched with threat_type from scan_results and override info.
// This is the admin-side equivalent of the user "Threats Blocked" counter.
router.get('/blocked', requireAdmin, can('threats'), async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 500;
    const { query } = require('../database/db');

    const result = await query(`
      SELECT e.email_id, e.user_id, e.gmail_message_id,
        u.email          AS user_email,
        u.username       AS user_name,
        e.sender_email, e.subject, e.received_date,
        e.confidence_score, e.scanned_at,
        e.spf_result, e.dkim_result, e.dmarc_result, e.has_attachment,
        sr.threat_type, sr.details,
        ov.new_level     AS override_level,
        ov.note          AS override_note,
        ov.overridden_by, ov.overridden_at
      FROM (
        SELECT DISTINCT ON (gmail_message_id, user_id)
               email_id, user_id, sender_email, subject, received_date,
               confidence_score, scanned_at, gmail_message_id,
               spf_result, dkim_result, dmarc_result, has_attachment
        FROM emails
        WHERE is_phishing = 1 AND gmail_message_id IS NOT NULL
        ORDER BY gmail_message_id, user_id, scanned_at DESC
      ) e
      LEFT JOIN users u ON e.user_id = u.user_id
      LEFT JOIN LATERAL (
        SELECT threat_type, details
        FROM scan_results
        WHERE email_id = e.email_id
        ORDER BY scan_timestamp DESC LIMIT 1
      ) sr ON TRUE
      LEFT JOIN LATERAL (
        SELECT new_level, note, overridden_by, overridden_at
        FROM threat_overrides
        WHERE email_id = e.email_id
        ORDER BY overridden_at DESC LIMIT 1
      ) ov ON TRUE
      ORDER BY e.scanned_at DESC
      LIMIT $1
    `, [limit]);

    const rows = result.rows;

    // Summary counts
    const dangerous  = rows.filter(r => {
      const lvl = r.override_level || r.threat_type;
      return lvl === 'dangerous';
    }).length;
    const suspicious = rows.filter(r => {
      const lvl = r.override_level || r.threat_type;
      return lvl === 'suspicious';
    }).length;
    const overridden = rows.filter(r => r.override_level).length;

    res.json({
      success: true,
      summary: { total: rows.length, dangerous, suspicious, overridden },
      blocked: rows.map(r => ({
        emailId:       r.email_id,
        userId:        r.user_id,
        userEmail:     r.user_email || '—',
        userName:      r.user_name  || '—',
        senderEmail:   r.sender_email,
        subject:       r.subject,
        receivedDate:  r.received_date,
        score:         Math.round((r.confidence_score || 0) * 100),
        scannedAt:     r.scanned_at,
        threatType:    r.override_level || r.threat_type || 'suspicious',
        details:       (() => { try { return JSON.parse(r.details || '[]'); } catch { return []; } })(),
        spf:           r.spf_result,
        dkim:          r.dkim_result,
        dmarc:         r.dmarc_result,
        hasAttachment: !!r.has_attachment,
        overrideLevel: r.override_level || null,
        overrideNote:  r.override_note  || null,
        overriddenBy:  r.overridden_by  || null,
        overriddenAt:  r.overridden_at  || null,
      }))
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── POST /admin/api/threats/:id/review ───────────────────────
router.post('/threats/:id/review', requireAdmin, can('review'), async (req, res) => {
  const { note, status } = req.body;
  try {
    await addThreatReview(req.params.id, req.session.admin.email, note, status || 'reviewed');
    await logActivity(req.session.admin.email, req.session.admin.role, 'THREAT_REVIEWED', `Reviewed threat ${req.params.id}: ${note||'no note'}`, getIP(req));
    res.json({ success: true, message: 'Threat marked as reviewed.' });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── POST /admin/api/threats/:id/override ─────────────────────
// Also aliased as PATCH (the admin modal uses PATCH)
async function handleOverride(req, res) {
  const { originalLevel, newLevel, note, adminRemark, overrideLevel } = req.body;
  const resolvedNew   = newLevel  || overrideLevel;
  const resolvedNote  = note      || adminRemark || '';
  if (!resolvedNew) return res.status(400).json({ success: false, error: 'newLevel required.' });
  if (!['safe','suspicious','dangerous'].includes(resolvedNew))
    return res.status(400).json({ success: false, error: 'newLevel must be safe, suspicious, or dangerous.' });
  try {
    // Use a default remark so the user always receives a notification,
    // even when the admin didn't write a custom reason
    const remarkForUser = resolvedNote.trim()
      || `An admin has reclassified this email from "${originalLevel || 'unknown'}" to "${resolvedNew}".`;

    await overrideThreatLevel(req.params.id, originalLevel, resolvedNew, req.session.admin.email, remarkForUser);
    await logActivity(req.session.admin.email, req.session.admin.role, 'ADMIN_THREAT_OVERRIDE',
      `Override threat ${req.params.id}: ${originalLevel} → ${resolvedNew}. Note: ${remarkForUser}`, getIP(req));
    res.json({ success: true, message: `Threat level overridden to ${resolvedNew}.` });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
}

router.post('/threats/:id/override',  requireAdmin, can('override_threat'), handleOverride);
router.patch('/threats/:id/override', requireAdmin, can('override_threat'), handleOverride);

// ── GET /admin/api/activity ───────────────────────────────────
router.get('/activity', requireAdmin, can('activity'), async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    res.json({ success: true, logs: await getActivityLog(limit) });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── GET /admin/api/admin-activity ────────────────────────────
router.get('/admin-activity', requireAdmin, can('admin_activity'), async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    res.json({ success: true, logs: await getAdminActivityLog(limit) });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── GET /admin/api/settings ───────────────────────────────────
router.get('/settings', requireAdmin, can('settings'), async (req, res) => {
  try {
    const rows = await getAllSystemSettings();
    const settings = {};
    rows.forEach(r => { settings[r.key] = r.value; });
    res.json({ success: true, settings });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── PUT /admin/api/settings ───────────────────────────────────
router.put('/settings', requireAdmin, can('settings'), async (req, res) => {
  const { key, value } = req.body;
  if (!key || value === undefined)
    return res.status(400).json({ success: false, error: 'key and value required.' });
  const mlKeys = ['threat_score_dangerous','threat_score_suspicious'];
  if (mlKeys.includes(key) && req.session.admin.role !== 'superadmin')
    return res.status(403).json({ success: false, error: 'Only Super Admin can change ML threat score thresholds.' });
  try {
    await updateSystemSetting(key, String(value), req.session.admin.email);
    await logActivity(req.session.admin.email, req.session.admin.role, 'SETTINGS_CHANGED', `Setting "${key}" changed to "${value}"`, getIP(req));
    res.json({ success: true, message: `Setting updated: ${key} = ${value}` });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── GET /admin/api/admins ─────────────────────────────────────
router.get('/admins', requireAdmin, can('admins'), async (req, res) => {
  try {
    const admins = (await getAllAdmins()).map(({ password, ...rest }) => rest);
    res.json({ success: true, admins });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── POST /admin/api/admins ────────────────────────────────────
router.post('/admins', requireAdmin, can('admins'), async (req, res) => {
  const { email, password, role, name } = req.body;
  if (!email || !password)
    return res.status(400).json({ success: false, error: 'Email and password required.' });
  if (!['viewer','moderator'].includes(role))
    return res.status(400).json({ success: false, error: 'Role must be viewer or moderator.' });
  try {
    if (await getAdminByEmail(email))
      return res.status(409).json({ success: false, error: 'Admin with this email already exists.' });
    const id = await createAdmin({ email, password, role, name: name || email.split('@')[0], createdBy: req.session.admin.email });
    await logActivity(req.session.admin.email, req.session.admin.role, 'ADMIN_CREATED', `Created admin: ${email} with role ${role}`, getIP(req));
    res.json({ success: true, adminId: id });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── PUT /admin/api/admins/:id/role ────────────────────────────
router.put('/admins/:id/role', requireAdmin, can('admins'), async (req, res) => {
  const { role } = req.body;
  if (!['viewer','moderator'].includes(role))
    return res.status(400).json({ success: false, error: 'Can only assign viewer or moderator.' });
  try {
    const admins = await getAllAdmins();
    const target = admins.find(a => a.admin_id === req.params.id);
    if (!target) return res.status(404).json({ success: false, error: 'Admin not found.' });
    if (target.role === 'superadmin') return res.status(403).json({ success: false, error: 'Cannot change Super Admin role.' });
    await updateAdminRole(req.params.id, role);
    await logActivity(req.session.admin.email, req.session.admin.role, 'ADMIN_ROLE_CHANGED', `Changed ${target.email} role to ${role}`, getIP(req));
    res.json({ success: true, message: `Role updated to ${ROLE_LABELS[role]}` });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── PUT /admin/api/admins/:id/toggle ─────────────────────────
router.put('/admins/:id/toggle', requireAdmin, can('admins'), async (req, res) => {
  try {
    const admins = await getAllAdmins();
    const target = admins.find(a => a.admin_id === req.params.id);
    if (!target) return res.status(404).json({ success: false, error: 'Admin not found.' });
    if (target.role === 'superadmin') return res.status(403).json({ success: false, error: 'Cannot deactivate Super Admin.' });
    await toggleAdminStatus(req.params.id);
    await logActivity(req.session.admin.email, req.session.admin.role, 'ADMIN_TOGGLED', `Toggled admin status: ${target.email}`, getIP(req));
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── DELETE /admin/api/admins/:id ──────────────────────────────
router.delete('/admins/:id', requireAdmin, can('admins'), async (req, res) => {
  try {
    const admins = await getAllAdmins();
    const target = admins.find(a => a.admin_id === req.params.id);
    if (!target) return res.status(404).json({ success: false, error: 'Admin not found.' });
    if (target.role === 'superadmin') return res.status(403).json({ success: false, error: 'Cannot delete Super Admin.' });
    await deleteAdmin(req.params.id);
    await logActivity(req.session.admin.email, req.session.admin.role, 'ADMIN_DELETED', `Deleted admin: ${target.email}`, getIP(req));
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── GET /admin/api/honeypot/sessions ─────────────────────────
router.get('/honeypot/sessions', requireAdmin, can('honeypot'), async (req, res) => {
  try {
    const sessions = await getAllHoneypotSessions();
    const now = Date.now();
    const enriched = sessions.map(s => {
      const startedAt   = s.started_at ? new Date(s.started_at).getTime() : now;
      const minutesWasted = s.status === 'active' ? Math.floor((now - startedAt) / 60000) : (s.minutes_wasted || 0);
      return {
        sessionId: s.session_id, userId: s.user_id, userEmail: s.user_email || null,
        userName: s.user_name || null, emailId: s.email_id, threadId: s.thread_id,
        senderEmail: s.sender_email, subject: s.subject,
        repliesSent: s.replies_sent || 0, minutesWasted,
        startedAt: s.started_at, lastReplyAt: s.last_reply_at, status: s.status || 'active'
      };
    });
    const stats = {
      total: enriched.length, active: enriched.filter(s => s.status === 'active').length,
      ended: enriched.filter(s => s.status === 'ended').length,
      totalReplies: enriched.reduce((a, s) => a + s.repliesSent, 0),
      totalMinutes: enriched.reduce((a, s) => a + s.minutesWasted, 0),
      uniqueAttackers: new Set(enriched.map(s => s.senderEmail).filter(Boolean)).size
    };
    res.json({ success: true, stats, sessions: enriched });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── DELETE /admin/api/honeypot/sessions/:sessionId ───────────
router.delete('/honeypot/sessions/:sessionId', requireAdmin, can('review'), async (req, res) => {
  try {
    const session = await getHoneypotSessionById(req.params.sessionId);
    if (session && session.started_at) {
      const elapsed = Math.floor((Date.now() - new Date(session.started_at).getTime()) / 60000);
      await updateHoneypotSession(req.params.sessionId, { minutes_wasted: elapsed, status: 'ended' });
    }
    await endHoneypotSession(req.params.sessionId);
    await logActivity(req.session.admin.email, req.session.admin.role, 'HONEYPOT_TERMINATED', `Terminated honeypot session: ${req.params.sessionId}`, getIP(req));
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── GET /admin/api/honeypot/sessions/:id/messages ────────────
router.get('/honeypot/sessions/:sessionId/messages', requireAdmin, can('honeypot'), async (req, res) => {
  try {
    const messages = await getHoneypotMessages(req.params.sessionId);
    res.json({ success: true, messages: messages.map(m => ({
      id:          m.message_id,
      direction:   m.direction,   // 'inbound' = scammer, 'outbound' = our persona
      from:        m.from_address,
      body:        m.body,
      sentAt:      m.sent_at,
      gmailMsgId:  m.gmail_msg_id
    }))});
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;

