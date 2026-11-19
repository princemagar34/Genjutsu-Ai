// admin/adminRoutes.js — Full RBAC async PostgreSQL version
const express = require('express');
const {
  getAdminByEmail, getAllAdmins, createAdmin, updateAdminRole, toggleAdminStatus, addThreatReview,
  logActivity, getActivityLog, getAdminActivityLog, getAllSystemSettings, updateSystemSetting,
  suspendUser, unsuspendUser, overrideThreatLevel, getAllHoneypotSessions, endHoneypotSession,
  updateHoneypotSession, getHoneypotSessionById, getHoneypotMessages
} = require('../database/db');

const router = express.Router();

const auth = require('./adminAuth');
const { getIP, requireAdmin, can } = require('./adminCore');
const ROLE_LABELS = require('./adminCore').ROLE_LABELS;

// Sign-in, sign-out and your own account live in adminLogin.js
router.use(require('./adminLogin'));
// Queue, attackers, block list, users, approvals, health, reports …
const extra = require('./adminExtra');
router.use(extra);
router.use(require('./adminOrgs'));

// ── GET /admin/api/stats ──────────────────────────────────────
router.get('/stats', requireAdmin, require('./orgScope').viewOrg, can('stats'), async (req, res) => {
  try { res.json({ success: true, stats: await require('../database/adminDb').systemStats() }); }
  catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── GET /admin/api/trend ──────────────────────────────────────
// Returns real per-day threat/safe counts for the Threat Trend chart.
// Replaces the fake estimate previously calculated in the frontend.
router.get('/trend', requireAdmin, require('./orgScope').viewOrg, can('stats'), async (req, res) => {
  try {
    const days = parseInt(req.query.days) || 7;
    const trend = await require('../database/adminDb').trend(Math.min(90, Math.max(1, days)));
    res.json({ success: true, trend });
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

// ── GET /admin/api/blocked ────────────────────────────────────
// Returns all emails flagged as phishing (is_phishing=1),
// enriched with threat_type from scan_results and override info.
// This is the admin-side equivalent of the user "Threats Blocked" counter.
router.get('/blocked', requireAdmin, require('./orgScope').viewOrg, can('threats'), async (req, res) => {
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
        sr.threat_type, sr.details, sr.origin_country, sr.mitre,
        ov.new_level     AS override_level,
        ov.note          AS override_note,
        ov.overridden_by, ov.overridden_at
      FROM (
        SELECT DISTINCT ON (gmail_message_id, user_id)
               email_id, user_id, sender_email, subject, received_date,
               confidence_score, scanned_at, gmail_message_id,
               spf_result, dkim_result, dmarc_result, has_attachment
        FROM emails
        WHERE is_phishing = 1 AND gmail_message_id IS NOT NULL AND ${require('./orgScope').realUser('user_id')}
        ORDER BY gmail_message_id, user_id, scanned_at DESC
      ) e
      LEFT JOIN users u ON e.user_id = u.user_id
      LEFT JOIN LATERAL (
        SELECT threat_type, details, origin_country, mitre
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
        country:       r.origin_country || null,
        mitre:         (() => { try { return JSON.parse(r.mitre || '[]'); } catch { return []; } })(),
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
  // Score thresholds change every user's verdicts: they go through approvals
  if (mlKeys.includes(key)) return extra.startAction(req, res, 'set_threshold', { key, value });
  try {
    await updateSystemSetting(key, String(value), req.session.admin.email);
    await logActivity(req.session.admin.email, req.session.admin.role, 'SETTINGS_CHANGED', `Setting "${key}" changed to "${value}"`, getIP(req));
    res.json({ success: true, message: `Setting updated: ${key} = ${value}` });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── GET /admin/api/admins ─────────────────────────────────────
router.get('/admins', requireAdmin, can('admins'), async (req, res) => {
  try {
    const admins = (await getAllAdmins()).map(({ password, totp_secret, recovery_codes, ...rest }) => rest);
    res.json({ success: true, admins });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── POST /admin/api/admins ────────────────────────────────────
router.post('/admins', requireAdmin, can('admins'), async (req, res) => {
  const { email, password, role, name } = req.body;
  if (!email || !password)
    return res.status(400).json({ success: false, error: 'Email and password required.' });
  const pwProblem = auth.passwordProblem(password);
  if (pwProblem) return res.status(400).json({ success: false, error: pwProblem });
  if (!['viewer','moderator'].includes(role))
    return res.status(400).json({ success: false, error: 'Role must be viewer or moderator.' });
  try {
    if (await getAdminByEmail(email))
      return res.status(409).json({ success: false, error: 'Admin with this email already exists.' });
    // orgId set = an organization admin who only sees that organization
    const orgId = req.body.orgId || null;
    if (orgId && !await require('../services/orgs').get(orgId)) return res.status(400).json({ success: false, error: 'Organization not found.' });
    const id = await createAdmin({ email, password: auth.hashPassword(password), role, name: name || email.split('@')[0], createdBy: req.session.admin.email, orgId });
    await logActivity(req.session.admin.email, req.session.admin.role, 'ADMIN_CREATED', `Created admin: ${email} with role ${role}${orgId ? ' for ' + orgId : ''}`, getIP(req));
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
    return extra.startAction(req, res, 'delete_admin', { adminId: req.params.id });   // needs a second admin when there is one
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── GET /admin/api/honeypot/sessions ─────────────────────────
router.get('/honeypot/sessions', requireAdmin, can('honeypot'), async (req, res) => {
  try {
    const inOrg = await require('./orgScope').scopedUserIds();   // null for the Super Admin
    const sessions = (await getAllHoneypotSessions()).filter(s => !String(s.user_id || '').startsWith('demo-') && (!inOrg || inOrg.has(s.user_id)));   // demo chats aren't real
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
    if (require('./orgScope').currentOrg()) {
      const s = await getHoneypotSessionById(req.params.sessionId);
      if (!s || !await require('./orgScope').userInScope(s.user_id)) return res.status(404).json({ success: false, error: 'Not found' });
    }
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

