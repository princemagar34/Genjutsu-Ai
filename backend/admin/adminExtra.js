// admin/adminExtra.js — queue, attackers, block list, origins, users, mistakes,
// scammer details, announcements, approvals, health, reports, CSV exports
const express = require('express');
const adb = require('../database/adminDb');
const db  = require('../database/db');
const nami = require('../services/nami');
const { requireAdmin, can, getIP, toCsv } = require('./adminCore');

const router = express.Router();
const ok   = (res, body) => res.json({ success: true, ...body });
const fail = (res, err, code = 500) => res.status(code).json({ success: false, error: err.message || String(err) });
const log  = (req, action, detail) => db.logActivity(req.session.admin.email, req.session.admin.role, action, detail, getIP(req)).catch(() => {});
const DOMAIN_RE = /^(?=.{3,253}$)([a-z0-9-]+\.)+[a-z]{2,}$/;
const cleanDomain = (d) => {
  let s = String(d || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^.*@/, '').replace(/^www\./, '');
  try { s = require('../services/detection').registrable(s); } catch (_) {}
  return DOMAIN_RE.test(s) ? s : null;
};
const NEVER_BLOCK = new Set(['gmail.com','googlemail.com','outlook.com','hotmail.com','live.com','yahoo.com','icloud.com','proton.me','protonmail.com','google.com','microsoft.com']);

// Who must approve a risky action? Returns null when the requester may do it now.
async function approvalNeeded(req) {
  if (req.session.admin.role !== 'superadmin') return 'superadmin';
  const { rows } = await db.query(`SELECT COUNT(*)::int AS n FROM admin_users WHERE role='superadmin' AND is_active=1 AND admin_id <> $1`, [req.session.admin.adminId]);
  return rows[0].n > 0 ? 'another superadmin' : null;    // the only superadmin can act alone
}

// ── Queue: things that need an admin ─────────────────────────
router.get('/queue', requireAdmin, can('queue'), async (req, res) => {
  try {
    const me = req.session.admin.email;
    const [done, attackers, mistakes, actions, problems, devices, intel] = await Promise.all([
      adb.doneKeys(), adb.topAttackers(3, 20), adb.mistakes(30), adb.listActions('pending'), adb.problemUsers(),
      db.query(`SELECT d.* FROM admin_devices d WHERE d.first_seen > NOW() - interval '3 days'
                AND (SELECT COUNT(*) FROM admin_devices x WHERE x.admin_email = d.admin_email) > 1 ORDER BY d.first_seen DESC`).then(r => r.rows),
      recentIntel(),
    ]);
    const items = [];
    for (const a of attackers) if (a.users >= 3 && !a.blocked)
      items.push({ key: `campaign:${a.domain}`, type: 'campaign', at: a.last_seen, title: `${a.domain} hit ${a.users} users`,
        sub: `${a.emails} emails · score up to ${a.max_score}${a.country ? ' · from ' + a.country : ''}`, ref: a.domain });
    for (const m of mistakes) if (!m.review)
      items.push({ key: `mistake:${m.email_id}`, type: 'mistake', at: m.overridden_at, title: `User marked a "${m.original_level}" email safe`,
        sub: `${m.sender_email || ''} · score ${m.score}`, ref: m.email_id });
    for (const a of actions)
      items.push({ key: `action:${a.action_id}`, type: 'approval', at: a.requested_at, title: a.summary, sub: `Asked by ${a.requested_by}`,
        ref: a.action_id, mine: a.requested_by === me });
    for (const u of problems)
      items.push({ key: `user:${u.user_id}:${u.last_scan_error_at ? new Date(u.last_scan_error_at).toISOString().slice(0, 10) : 'stale'}`, type: 'user',
        at: u.last_scan_error_at || u.last_login, title: u.last_scan_error ? `Scans failing for ${u.email}` : `${u.email} hasn't been scanned in a week`,
        sub: u.last_scan_error ? String(u.last_scan_error).slice(0, 90) : 'They signed in recently but nothing was scanned', ref: u.user_id });
    for (const d of devices)
      items.push({ key: `device:${d.admin_email}:${d.device_hash.slice(0, 12)}`, type: 'login', at: d.first_seen,
        title: `Admin login from a new device`, sub: `${d.admin_email} · ${d.label || ''} · ${d.ip || ''}`, ref: d.admin_email });
    for (const s of intel)
      items.push({ key: `intel:${s.sessionId}:${s.count}`, type: 'nami', at: s.at, title: `Scammer shared ${s.what}`,
        sub: `${s.scammer} · ready to report`, ref: s.sessionId });
    const open = items.filter(i => !done.has(i.key)).sort((a, b) => new Date(b.at) - new Date(a.at));
    const counts = open.reduce((c, i) => (c[i.type] = (c[i.type] || 0) + 1, c), {});
    ok(res, { items: open, counts });
  } catch (err) { fail(res, err); }
});
router.post('/queue/done', requireAdmin, can('queue'), async (req, res) => {
  const key = String(req.body?.key || '').slice(0, 300);
  if (!key) return fail(res, 'key required', 400);
  try { await adb.markDone(key, req.session.admin.email); await log(req, 'QUEUE_DONE', key); ok(res, {}); } catch (err) { fail(res, err); }
});

async function recentIntel() {
  const rows = await adb.honeypotInbound();
  const by = new Map();
  for (const r of rows) {
    if (Date.now() - new Date(r.sent_at) > 7 * 864e5) continue;
    const i = nami.extractIntel(r.body, { exclude: [r.sender_email, r.user_email] });
    const n = Object.values(i).reduce((a, v) => a + v.length, 0);
    if (!n) continue;
    const cur = by.get(r.session_id) || { sessionId: r.session_id, scammer: r.sender_email, at: r.sent_at, count: 0, kinds: new Set() };
    cur.count += n; for (const [k, v] of Object.entries(i)) if (v.length) cur.kinds.add(k);
    by.set(r.session_id, cur);
  }
  const words = { bankAccounts: 'a bank account', ibans: 'an IBAN', crypto: 'a crypto wallet', phones: 'a phone number', whatsapp: 'a WhatsApp number', telegram: 'a Telegram account', emails: 'an email address', urls: 'a link' };
  return [...by.values()].map(s => ({ ...s, what: [...s.kinds].map(k => words[k] || k).slice(0, 2).join(' and ') }));
}

// ── Wall: live numbers ───────────────────────────────────────
router.get('/wall', requireAdmin, can('stats'), async (req, res) => {
  try {
    const [counts, hourly, feed, origins, attackers, health] = await Promise.all([
      adb.counts24h(), adb.hourly(), adb.liveFeed(25), adb.origins(7), adb.topAttackers(7, 8),
      require('./orgScope').currentOrg() ? null : adb.health()]);   // system health is everyone's data: Super Admin only
    ok(res, { counts, hourly, feed, origins, attackers, health });
  } catch (err) { fail(res, err); }
});

// ── Top attackers + one attacker in detail ───────────────────
router.get('/attackers', requireAdmin, can('attackers'), async (req, res) => {
  try { ok(res, { attackers: await adb.topAttackers(Math.min(90, parseInt(req.query.days) || 7), 50), origins: await adb.origins(Math.min(90, parseInt(req.query.days) || 7)) }); }
  catch (err) { fail(res, err); }
});
router.get('/attackers/:domain', requireAdmin, can('attackers'), async (req, res) => {
  const d = cleanDomain(req.params.domain);
  if (!d) return fail(res, 'Not a domain', 400);
  try {
    const rows = await adb.attackerDetail(d);
    const parse = (s) => { try { return JSON.parse(s || '[]'); } catch { return []; } };
    const users = {};
    rows.forEach(r => { const u = users[r.user_email] || (users[r.user_email] = { user: r.user_email, emails: 0, quarantined: 0 }); u.emails++; if (r.quarantined) u.quarantined++; });
    const reasons = {}; rows.forEach(r => parse(r.details).forEach(x => { reasons[x] = (reasons[x] || 0) + 1; }));
    const mitre = {}; rows.forEach(r => parse(r.mitre).forEach(m => { mitre[m.id] = m; }));
    const countries = {}; rows.forEach(r => { if (r.origin_country) countries[r.origin_country] = (countries[r.origin_country] || 0) + 1; });
    const blocked = (await db.query('SELECT * FROM global_blocklist WHERE domain=$1', [d])).rows[0] || null;
    let age = null; try { age = await require('../services/detection').domainAgeDays(d); } catch (_) {}
    ok(res, { domain: d, blocked, ageDays: age, emails: rows.length, users: Object.values(users),
      reasons: Object.entries(reasons).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([text, n]) => ({ text, n })),
      mitre: Object.values(mitre), countries, ips: [...new Set(rows.map(r => r.origin_ip).filter(Boolean))].slice(0, 10),
      firstSeen: rows.at(-1)?.scanned_at || null, lastSeen: rows[0]?.scanned_at || null,
      lookalike: require('../services/detection').lookalikeBrand(d)?.brand || null });
  } catch (err) { fail(res, err); }
});

// ── Global block list ────────────────────────────────────────
router.get('/blocklist', requireAdmin, can('attackers'), async (req, res) => {
  try { ok(res, { domains: await adb.listBlocklist() }); } catch (err) { fail(res, err); }
});
router.post('/blocklist', requireAdmin, can('blocklist'), async (req, res) => {
  const d = cleanDomain(req.body?.domain);
  if (!d) return fail(res, 'Enter a domain like bad-site.com', 400);
  if (NEVER_BLOCK.has(d)) return fail(res, `${d} is a big email provider. Blocking it would block real people. Block the exact sender with a rule instead.`, 400);
  try {
    await adb.addBlock(d, String(req.body?.reason || '').slice(0, 200), req.session.admin.email);
    await log(req, 'GLOBAL_BLOCK_ADD', `Blocked ${d} for everyone${req.body?.reason ? ': ' + req.body.reason : ''}`);
    ok(res, { domain: d });
  } catch (err) { fail(res, err); }
});
router.delete('/blocklist/:domain', requireAdmin, can('blocklist'), async (req, res) => {
  try {
    await adb.removeBlock(String(req.params.domain).toLowerCase());
    await log(req, 'GLOBAL_BLOCK_REMOVE', `Unblocked ${req.params.domain}`);
    ok(res, {});
  } catch (err) { fail(res, err); }
});

// ── Users ────────────────────────────────────────────────────
router.get('/users/list', requireAdmin, can('users'), async (req, res) => {
  try { ok(res, { users: await adb.userList() }); } catch (err) { fail(res, err); }
});
router.get('/users/:id/detail', requireAdmin, can('users'), async (req, res) => {
  try {
    if (!await require('./orgScope').userInScope(req.params.id)) return fail(res, 'User not found', 404);
    const d = await adb.userDetail(req.params.id);
    if (!d) return fail(res, 'User not found', 404);
    await log(req, 'VIEW_USER', `Opened ${d.user.email}`);
    ok(res, d);
  } catch (err) { fail(res, err); }
});

// ── One person's checked emails (Genjutsu team only: organization admins see threats only) ──
// Sender, subject, verdict and reasons — the scan record. The message text is never sent.
router.get('/users/:id/emails', requireAdmin, can('users'), async (req, res) => {
  if (req.session.admin.orgId) return fail(res, 'Not allowed', 403);
  try {
    const limit = Math.min(1000, Math.max(1, parseInt(req.query.limit) || 300));
    const u = (await db.query('SELECT user_id, email FROM users WHERE user_id=$1', [req.params.id])).rows[0];
    if (!u) return fail(res, 'User not found', 404);
    const rows = (await db.query(`
      SELECT e.email_id, e.sender_email, e.subject, e.received_date, e.scanned_at, e.has_attachment,
             ROUND(e.confidence_score*100)::int AS score, sr.threat_type, sr.details, ov.new_level AS override, ov.note AS override_note,
             EXISTS (SELECT 1 FROM blocked_emails b WHERE b.email_id = e.email_id) AS quarantined
      FROM emails e
      LEFT JOIN LATERAL (SELECT threat_type, details FROM scan_results WHERE email_id = e.email_id ORDER BY scan_timestamp DESC LIMIT 1) sr ON TRUE
      LEFT JOIN LATERAL (SELECT new_level, note FROM threat_overrides WHERE email_id = e.email_id ORDER BY overridden_at DESC LIMIT 1) ov ON TRUE
      WHERE e.user_id = $1 ORDER BY e.scanned_at DESC LIMIT $2`, [u.user_id, limit])).rows;
    const parse = (v) => { try { return JSON.parse(v || '[]'); } catch { return []; } };
    const when = (r) => { const t = Date.parse(r.received_date); return Number.isFinite(t) ? new Date(t) : null; };
    const emails = rows.map(r => ({ id: r.email_id, sender_email: r.sender_email, subject: r.subject, received_at: when(r), scanned_at: r.scanned_at,
      has_attachment: !!r.has_attachment, score: r.score || 0, level: r.override || r.threat_type || 'safe', override: r.override, override_note: r.override_note,
      reasons: parse(r.details), quarantined: r.quarantined }));
    const counts = { dangerous: 0, suspicious: 0, safe: 0 };
    emails.forEach(m => { counts[m.level in counts ? m.level : 'safe']++; });
    await log(req, 'VIEW_USER_EMAILS', `Opened the email list of ${u.email}`);
    ok(res, { user: u, total: emails.length, counts, emails });
  } catch (err) { fail(res, err); }
});

// ── Mistakes review ──────────────────────────────────────────
router.get('/mistakes', requireAdmin, can('mistakes'), async (req, res) => {
  try {
    const rows = await adb.mistakes(200);
    ok(res, { mistakes: rows.map(r => ({ ...r, details: (() => { try { return JSON.parse(r.details || '[]'); } catch { return []; } })() })) });
  } catch (err) { fail(res, err); }
});

// ── Scammer details collected by Nami (all users) ────────────
async function intelRows() {
  const out = [];
  for (const r of await adb.honeypotInbound()) {
    const i = nami.extractIntel(r.body, { exclude: [r.sender_email, r.user_email] });
    for (const [type, vals] of Object.entries(i))
      for (const value of vals) out.push({ type, value, scammer: r.sender_email, subject: r.subject, user: r.user_email, session: r.session_id, seen: r.sent_at });
  }
  const seen = new Set();
  return out.filter(x => { const k = `${x.type}|${x.value}|${x.session}`; if (seen.has(k)) return false; seen.add(k); return true; });
}
router.get('/intel', requireAdmin, can('intel'), async (req, res) => {
  try {
    const rows = await intelRows();
    const totals = rows.reduce((t, r) => (t[r.type] = (t[r.type] || 0) + 1, t), {});
    ok(res, { rows, totals, leaderboard: await adb.leaderboard() });
  } catch (err) { fail(res, err); }
});
router.get('/intel.csv', requireAdmin, can('intel'), async (req, res) => {
  try {
    const rows = await intelRows();
    await log(req, 'EXPORT_INTEL', `Downloaded ${rows.length} scammer details`);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="genjutsu-scammer-details-${new Date().toISOString().slice(0, 10)}.csv"`);
    res.send(toCsv(rows, ['type', 'value', 'scammer', 'subject', 'seen', 'session']));
  } catch (err) { fail(res, err); }
});
router.get('/honeypot/leaderboard', requireAdmin, can('honeypot'), async (req, res) => {
  try { ok(res, { leaderboard: await adb.leaderboard() }); } catch (err) { fail(res, err); }
});

// ── Announcements ────────────────────────────────────────────
router.get('/announcements', requireAdmin, can('stats'), async (req, res) => {
  try { ok(res, { announcements: await adb.listAnnouncements() }); } catch (err) { fail(res, err); }
});
router.post('/announcements', requireAdmin, can('announce'), async (req, res) => {
  const message = String(req.body?.message || '').trim();
  const level = ['info', 'warning', 'critical'].includes(req.body?.level) ? req.body.level : 'info';
  if (message.length < 3 || message.length > 280) return fail(res, 'Write 3 to 280 characters.', 400);
  const hours = Math.min(24 * 30, Math.max(0, parseInt(req.body?.hours) || 0));
  try {
    const id = await adb.addAnnouncement({ message, level, by: req.session.admin.email, expiresAt: hours ? new Date(Date.now() + hours * 36e5) : null });
    await log(req, 'ANNOUNCEMENT', `Posted (${level}): ${message}`);
    ok(res, { id });
  } catch (err) { fail(res, err); }
});
router.delete('/announcements/:id', requireAdmin, can('announce'), async (req, res) => {
  try { await adb.endAnnouncement(req.params.id); await log(req, 'ANNOUNCEMENT_END', req.params.id); ok(res, {}); } catch (err) { fail(res, err); }
});

// ── Approvals ────────────────────────────────────────────────
const ACTIONS = {
  delete_admin: {
    perm: 'admins',
    async describe(p) { const a = (await db.query('SELECT email, role FROM admin_users WHERE admin_id=$1', [p.adminId])).rows[0]; if (!a) throw new Error('Admin not found'); if (a.role === 'superadmin') throw new Error('Super Admin cannot be deleted.'); return `Delete admin ${a.email}`; },
    async run(p) { await db.deleteAdmin(p.adminId); },
  },
  set_threshold: {
    perm: 'settings',
    async describe(p) {
      if (!['threat_score_dangerous', 'threat_score_suspicious'].includes(p.key)) throw new Error('Not a threshold');
      const v = parseInt(p.value); if (!(v >= 10 && v <= 100)) throw new Error('Pick a number from 10 to 100');
      return `Change ${p.key === 'threat_score_dangerous' ? 'the "dangerous" score' : 'the "suspicious" score'} to ${v}`;
    },
    async run(p, by) { await db.updateSystemSetting(p.key, String(parseInt(p.value)), by); },
  },
  reset_2fa: {
    perm: 'admins',
    async describe(p) { const a = (await db.query('SELECT email FROM admin_users WHERE admin_id=$1', [p.adminId])).rows[0]; if (!a) throw new Error('Admin not found'); return `Turn off 2-step login for ${a.email} (lost phone)`; },
    async run(p) { await adb.setAdminTotp(p.adminId, { secret: null, enabled: false, recovery: null }); },
  },
};
async function startAction(req, res, action, payload) {
  const def = ACTIONS[action];
  const role = req.session.admin.role;
  if (!def) return fail(res, 'Unknown action', 400);
  if (!require('./adminCore').PERMISSIONS[role].includes(def.perm) && !require('./adminCore').PERMISSIONS[role].includes('request'))
    return fail(res, 'Your role cannot ask for this.', 403);
  try {
    const summary = await def.describe(payload);
    const who = await approvalNeeded(req);
    if (!who) {
      await def.run(payload, req.session.admin.email);
      await log(req, `ACTION_${action.toUpperCase()}`, `${summary} (only Super Admin, done directly)`);
      return ok(res, { done: true, message: `${summary}: done.` });
    }
    const id = await adb.requestAction(action, payload, summary, req.session.admin.email);
    await log(req, 'APPROVAL_REQUESTED', `${summary}: waiting for ${who}`);
    require('../services/teamAlerts').security(`${req.session.admin.email} asked for approval: ${summary}. Decide in the Queue.`);
    ok(res, { pending: true, id, message: `Sent for approval. ${who[0].toUpperCase() + who.slice(1)} must approve it.` });
  } catch (err) { fail(res, err, 400); }
}
router.post('/actions', requireAdmin, async (req, res) => startAction(req, res, req.body?.action, req.body?.payload || {}));
router.get('/actions', requireAdmin, can('queue'), async (req, res) => {
  try { ok(res, { pending: await adb.listActions('pending'), recent: [...await adb.listActions('approved'), ...await adb.listActions('rejected')].slice(0, 20) }); }
  catch (err) { fail(res, err); }
});
router.post('/actions/:id/:decision(approve|reject)', requireAdmin, can('approve'), async (req, res) => {
  try {
    const a = await adb.getAction(req.params.id);
    if (!a || a.status !== 'pending') return fail(res, 'Nothing to decide.', 404);
    if (a.requested_by === req.session.admin.email) return fail(res, 'Someone else has to approve your own request.', 403);
    if (req.params.decision === 'approve') await ACTIONS[a.action].run(JSON.parse(a.payload || '{}'), req.session.admin.email);
    await adb.decideAction(a.action_id, req.params.decision === 'approve' ? 'approved' : 'rejected', req.session.admin.email);
    await adb.markDone(`action:${a.action_id}`, req.session.admin.email);
    await log(req, req.params.decision === 'approve' ? 'APPROVED' : 'REJECTED', `${a.summary} (asked by ${a.requested_by})`);
    ok(res, {});
  } catch (err) { fail(res, err); }
});

// ── Detection model: what it learned from, versions, retrain ──
const trainer = () => require('../services/modelTrainer');
router.get('/model', requireAdmin, can('stats'), async (req, res) => {
  try { ok(res, await trainer().overview()); } catch (err) { fail(res, err); }
});
router.post('/model/train', requireAdmin, can('ml_settings'), async (req, res) => {
  try {
    const r = await trainer().train({ by: req.session.admin.email, force: true });
    await log(req, 'MODEL_TRAINED', r.message);
    ok(res, r);
  } catch (err) { fail(res, err); }
});
router.post('/model/:id/activate', requireAdmin, can('ml_settings'), async (req, res) => {
  try {
    const v = await trainer().activate(req.params.id);
    await log(req, 'MODEL_SWITCHED', `Switched the live model to ${v}`);
    ok(res, { version: v });
  } catch (err) { fail(res, err, 400); }
});
router.post('/model/samples/:id/exclude', requireAdmin, can('review'), async (req, res) => {
  try {
    await trainer().excludeSample(req.params.id, req.body?.on !== false);
    await log(req, 'TRAINING_SAMPLE', `${req.body?.on === false ? 'Put back' : 'Left out'} example ${req.params.id}`);
    ok(res, {});
  } catch (err) { fail(res, err); }
});

// ── Maintenance: re-sort every saved threat with the current rules ──
router.post('/maintenance/reclassify', requireAdmin, can('ml_settings'), async (req, res) => {
  try {
    const r = await require('../services/threatRecords').reclassifyAll(db.query);
    await log(req, 'RECLASSIFY', `Re-sorted saved threats: ${r.changed} of ${r.checked} changed`);
    ok(res, r);
  } catch (err) { fail(res, err); }
});

// ── Shared threat feed ───────────────────────────────────────
const feed = () => require('../services/sharedFeed');
router.get('/shared-feed', requireAdmin, can('attackers'), async (req, res) => {
  try { ok(res, { indicators: await feed().list(), minUsers: feed().MIN_USERS }); } catch (err) { fail(res, err); }
});
router.post('/shared-feed/rebuild', requireAdmin, can('blocklist'), async (req, res) => {
  try { const r = await feed().rebuild(); await log(req, 'SHARED_FEED', `Rebuilt: ${r.active} active of ${r.indicators}`); ok(res, r); } catch (err) { fail(res, err); }
});
router.post('/shared-feed/:kind(domain|sender)/:status(removed|active)', requireAdmin, can('blocklist'), async (req, res) => {
  const value = String(req.body?.value || '').toLowerCase().slice(0, 300);
  if (!value) return fail(res, 'value required', 400);
  try {
    await feed().setStatus(req.params.kind, value, req.params.status, req.session.admin.email);
    await log(req, 'SHARED_FEED', `${req.params.status === 'removed' ? 'Removed' : 'Put back'} ${req.params.kind} ${value}`);
    ok(res, {});
  } catch (err) { fail(res, err); }
});

// ── Team alerts (Discord / email) ────────────────────────────
router.get('/team-alerts', requireAdmin, can('settings'), async (req, res) => {
  try { ok(res, { status: await require('../services/teamAlerts').status(), cap: require('../services/teamAlerts').HOURLY_THREAT_CAP }); } catch (err) { fail(res, err); }
});
router.put('/team-alerts/discord', requireAdmin, can('ml_settings'), async (req, res) => {
  try {
    await require('../services/teamAlerts').setDiscord(String(req.body?.url || '').trim(), req.session.admin.email);
    await log(req, 'TEAM_ALERTS', req.body?.url ? 'Connected the team Discord' : 'Removed the team Discord');
    ok(res, {});
  } catch (err) { fail(res, err, 400); }
});
router.post('/team-alerts/test', requireAdmin, can('settings'), async (req, res) => {
  try {
    const r = await require('../services/teamAlerts').test();
    if (!r.discord && !r.email && !r.telegram) return fail(res, 'No team alert channel is set up yet, or it did not answer.', 400);
    ok(res, { sent: r });
  } catch (err) { fail(res, err); }
});

// ── Health ───────────────────────────────────────────────────
router.get('/health', requireAdmin, can('health'), async (req, res) => {
  try { ok(res, { health: await adb.health(), problems: await adb.problemUsers() }); } catch (err) { fail(res, err); }
});

// ── CSV downloads of the logs ────────────────────────────────
router.get('/admin-activity.csv', requireAdmin, can('admin_activity'), async (req, res) => {
  try {
    const rows = await db.getAdminActivityLog(5000);
    await log(req, 'EXPORT_ADMIN_LOG', `Downloaded ${rows.length} rows`);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="genjutsu-admin-log-${new Date().toISOString().slice(0, 10)}.csv"`);
    res.send(toCsv(rows, ['logged_at', 'admin_email', 'admin_role', 'action', 'detail', 'ip_address']));
  } catch (err) { fail(res, err); }
});

// ── Monthly report (PDF) ─────────────────────────────────────
router.get('/report/monthly', requireAdmin, can('reports'), async (req, res) => {
  const now = new Date();
  const m = String(req.query.month || '').match(/^(\d{4})-(\d{2})$/);
  const year = m ? +m[1] : now.getUTCFullYear(), month = m ? +m[2] : now.getUTCMonth() + 1;
  if (month < 1 || month > 12) return fail(res, 'Month must look like 2026-11', 400);
  try {
    const data = await adb.monthReport(year, month);
    await log(req, 'REPORT_MONTHLY', `${year}-${String(month).padStart(2, '0')}`);
    require('../services/adminReport').monthlyPdf(res, data, { year, month, by: req.session.admin.email });
  } catch (err) { if (!res.headersSent) fail(res, err); }
});

module.exports = router;
module.exports.ACTIONS = ACTIONS;
module.exports.cleanDomain = cleanDomain;
module.exports.startAction = startAction;
