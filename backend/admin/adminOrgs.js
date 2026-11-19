// admin/adminOrgs.js — organizations/organizations.
// Super Admin: create organizations, set the plan, pause an organization, see any organization.
// Organization admin (moderator): invite links and members of their own organization only.
const express = require('express');
const orgs = require('../services/orgs');
const { requireAdmin, can, getIP } = require('./adminCore');
const { logActivity } = require('../database/db');
const router = express.Router();
const ok = (res, d) => res.json({ success: true, ...d });
const fail = (res, e, code = 500) => res.status(code).json({ success: false, error: e?.message || e });
const log = (req, action, detail) => logActivity(req.session.admin.email, req.session.admin.role, action, detail, getIP(req)).catch(() => {});

// An organization admin always works on their own organization; the Super Admin picks one with ?org= / body.org
function targetOrg(req) {
  const a = req.session.admin;
  if (a.orgId) return a.orgId;
  const o = req.body?.org || req.query.org || require('./orgScope').currentOrg();
  return a.role === 'superadmin' && orgs.isOrgId(o) ? o : null;
}
const inviteUrl = (req, code) => `${req.protocol}://${req.get('host')}/?join=${encodeURIComponent(code)}`;

router.get('/org', requireAdmin, async (req, res) => {
  const id = targetOrg(req); if (!id) return fail(res, 'Pick an organization.', 400);
  try {
    const org = await orgs.get(id); if (!org) return fail(res, 'Not found', 404);
    const { query } = require('../database/db');
    const members = (await query(`SELECT u.user_id, u.email, u.username, u.org_joined, u.last_login, u.last_scan_at,
        (SELECT COUNT(*)::int FROM emails e WHERE e.user_id = u.user_id AND e.is_phishing = 1) AS threats
      FROM users u WHERE u.org_id=$1 ORDER BY u.last_login DESC NULLS LAST`, [id])).rows;
    const invites = (await orgs.invites(id)).map(i => ({ ...i, url: inviteUrl(req, i.code) }));
    ok(res, { org: { ...org, plan_label: orgs.PLANS[org.plan]?.label || org.plan }, members, invites, allowed: await orgs.allowedEmails(id), seatsUsed: members.length, plans: orgs.PLANS });
  } catch (e) { fail(res, e); }
});
router.post('/org/invites', requireAdmin, can('org'), async (req, res) => {
  const id = targetOrg(req); if (!id) return fail(res, 'Pick an organization.', 400);
  try {
    const code = await orgs.createInvite(id, req.session.admin.email, { days: parseInt(req.body?.days) || 14, maxUses: parseInt(req.body?.maxUses) || 50 });
    await log(req, 'ORG_INVITE', `Invite link created for ${id}`);
    ok(res, { code, url: inviteUrl(req, code) });
  } catch (e) { fail(res, e, 400); }
});
router.delete('/org/invites/:code', requireAdmin, can('org'), async (req, res) => {
  const id = targetOrg(req); if (!id) return fail(res, 'Pick an organization.', 400);
  try { await orgs.revokeInvite(id, req.params.code); await log(req, 'ORG_INVITE_REVOKED', id); ok(res, {}); } catch (e) { fail(res, e); }
});
router.post('/org/members/:id/remove', requireAdmin, can('org'), async (req, res) => {
  const id = targetOrg(req); if (!id) return fail(res, 'Pick an organization.', 400);
  try {
    if (!await orgs.removeMember(id, req.params.id)) return fail(res, 'Not a member of this organization.', 404);
    await log(req, 'ORG_MEMBER_REMOVED', `${req.params.id} removed from ${id}`);
    ok(res, {});
  } catch (e) { fail(res, e); }
});

// People added by email: they join when they sign in to Genjutsu (or right away if they already use it)
router.post('/org/allowed', requireAdmin, can('org'), async (req, res) => {
  const id = targetOrg(req); if (!id) return fail(res, 'Pick an organization.', 400);
  try {
    const r = await orgs.addEmails(id, String(req.body?.emails || '').slice(0, 40000), req.session.admin.email);
    if (r.added.length) await log(req, 'ORG_EMAILS_ADDED', `${r.added.length} address(es) added to ${id}`);
    ok(res, r);
  } catch (e) { fail(res, e, 400); }
});
router.delete('/org/allowed/:email', requireAdmin, can('org'), async (req, res) => {
  const id = targetOrg(req); if (!id) return fail(res, 'Pick an organization.', 400);
  try { await orgs.removeEmail(id, req.params.email); await log(req, 'ORG_EMAIL_REMOVED', `${req.params.email} from ${id}`); ok(res, {}); } catch (e) { fail(res, e); }
});

// ── Super Admin only ─────────────────────────────────────────
router.get('/orgs', requireAdmin, can('orgs'), async (req, res) => {
  try { ok(res, { orgs: await orgs.list(), plans: orgs.PLANS }); } catch (e) { fail(res, e); }
});
router.post('/orgs', requireAdmin, can('orgs'), async (req, res) => {
  try {
    const b = req.body || {};
    const id = await orgs.create({ name: b.name, domains: b.domains, plan: b.plan, by: req.session.admin.email });
    await log(req, 'ORG_CREATED', `${b.name} (${id})`);
    ok(res, { orgId: id });
  } catch (e) { fail(res, e, 400); }
});
router.put('/orgs/:id', requireAdmin, can('orgs'), async (req, res) => {
  try {
    const b = req.body || {};
    await orgs.update(req.params.id, { name: b.name, domains: b.domains, plan: b.plan, status: b.status });
    await log(req, 'ORG_UPDATED', `${req.params.id}: ${JSON.stringify({ plan: b.plan, status: b.status })}`);
    ok(res, {});
  } catch (e) { fail(res, e, 400); }
});

module.exports = router;
