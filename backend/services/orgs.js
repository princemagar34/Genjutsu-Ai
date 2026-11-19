// services/orgs.js — organizations (organizations, companies, any team). Each organization's admins see only
// that organization's users and data; only the Super Admin sees everything.
//
// Joining: staff whose email ends in one of the organization's domains join automatically when
// they sign in; anyone else joins with an invite link. There is no member limit.
// Plans: 'free' or 'paid', set by the Super Admin (no payments yet). Plans don't limit members.
const crypto = require('crypto');
const db = () => require('../database/db');
const { FREE_MAIL } = require('./detection');

const ORG_ID = /^org-[a-f0-9]{16}$/;
const isOrgId = (v) => ORG_ID.test(String(v || ''));
const PLANS = { free: { label: 'Free' }, paid: { label: 'Paid' } };
const planKey = (p) => p === 'school' ? 'paid' : p;   // old name

async function initOrgs() {
  await db().query(`
    CREATE TABLE IF NOT EXISTS organisations (
      org_id     TEXT PRIMARY KEY,
      name       TEXT NOT NULL,
      domains    TEXT DEFAULT '',            -- comma separated, e.g. organization.edu.np
      plan       TEXT DEFAULT 'free',
      seat_limit INTEGER DEFAULT 5,
      status     TEXT DEFAULT 'active',      -- active | suspended
      created_by TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS org_invites (
      code       TEXT PRIMARY KEY,
      org_id     TEXT NOT NULL,
      created_by TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      expires_at TIMESTAMPTZ,
      max_uses   INTEGER DEFAULT 50,
      uses       INTEGER DEFAULT 0,
      revoked    INTEGER DEFAULT 0
    );
    ALTER TABLE users        ADD COLUMN IF NOT EXISTS org_id     TEXT;
    ALTER TABLE users        ADD COLUMN IF NOT EXISTS org_joined TEXT;      -- domain | invite | admin
    ALTER TABLE users        ADD COLUMN IF NOT EXISTS org_optout TEXT;      -- removed from this org: never auto-join it again
    ALTER TABLE admin_users  ADD COLUMN IF NOT EXISTS org_id     TEXT;      -- NULL only for the Super Admin
    ALTER TABLE activity_log ADD COLUMN IF NOT EXISTS org_id     TEXT;
    ALTER TABLE announcements ADD COLUMN IF NOT EXISTS org_id    TEXT;      -- NULL = everyone
    CREATE INDEX IF NOT EXISTS users_org ON users (org_id);
    UPDATE organisations SET plan='paid' WHERE plan='school';
    -- People an organization added by email (works for Gmail too). One organization per address.
    CREATE TABLE IF NOT EXISTS org_allowed_emails (
      email    TEXT PRIMARY KEY,            -- lower case
      org_id   TEXT NOT NULL,
      added_by TEXT,
      added_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS org_allowed_org ON org_allowed_emails (org_id);
    -- The Super Admin is never tied to one organization
    UPDATE admin_users SET org_id = NULL WHERE role = 'superadmin' AND org_id IS NOT NULL;
  `);
}

// "it@school.edu.np" or "@school.edu.np" → school.edu.np
const cleanDomains = (list) => [...new Set(String(list || '').split(/[\s,;]+/).map(d => d.trim().toLowerCase().replace(/^.*@/, '')).filter(Boolean))];
function domainProblem(domains) {
  for (const d of domains) {
    if (!/^([a-z0-9-]+\.)+[a-z]{2,}$/.test(d)) return `"${d}" is not a domain`;
    if (FREE_MAIL.has(d)) return `${d} is a public email service. Only an organization's own domain can be used`;
  }
  return null;
}

async function list() {
  return (await db().query(`SELECT o.*, (SELECT COUNT(*)::int FROM users u WHERE u.org_id = o.org_id) AS members,
           (SELECT COUNT(*)::int FROM admin_users a WHERE a.org_id = o.org_id AND a.is_active = 1) AS admins
    FROM organisations o ORDER BY o.created_at DESC`)).rows;
}
const get = async (orgId) => isOrgId(orgId) ? (await db().query('SELECT * FROM organisations WHERE org_id=$1', [orgId])).rows[0] || null : null;
const seatsUsed = async (orgId) => (await db().query('SELECT COUNT(*)::int AS n FROM users WHERE org_id=$1', [orgId])).rows[0].n;

async function create({ name, domains, plan = 'free', by }) {
  plan = planKey(plan);
  name = String(name || '').trim().slice(0, 120);
  if (name.length < 2) throw new Error('Give the organization a name.');
  const ds = cleanDomains(domains); const bad = domainProblem(ds); if (bad) throw new Error(bad);
  for (const d of ds) if ((await db().query(`SELECT 1 FROM organisations WHERE ',' || domains || ',' LIKE '%,' || $1 || ',%'`, [d])).rows.length) throw new Error(`${d} already belongs to another organization.`);
  if (!PLANS[plan]) throw new Error('Unknown plan.');
  const id = `org-${crypto.randomBytes(8).toString('hex')}`;
  await db().query('INSERT INTO organisations (org_id, name, domains, plan, created_by) VALUES ($1,$2,$3,$4,$5)',
    [id, name, ds.join(','), plan, by]);
  await backfill(id);
  return id;
}
async function update(orgId, { name, domains, plan, status }) {
  const org = await get(orgId); if (!org) throw new Error('Organization not found.');
  const next = { name: name != null ? String(name).trim().slice(0, 120) : org.name, plan: planKey(plan || org.plan),
    status: status || org.status, domains: org.domains };
  if (domains != null) {
    const ds = cleanDomains(domains); const bad = domainProblem(ds); if (bad) throw new Error(bad);
    for (const d of ds) if ((await db().query(`SELECT 1 FROM organisations WHERE org_id<>$2 AND ',' || domains || ',' LIKE '%,' || $1 || ',%'`, [d, orgId])).rows.length) throw new Error(`${d} already belongs to another organization.`);
    next.domains = ds.join(',');
  }
  if (!PLANS[next.plan]) throw new Error('Unknown plan.');
  if (!['active', 'suspended'].includes(next.status)) throw new Error('Unknown status.');
  await db().query('UPDATE organisations SET name=$2, domains=$3, plan=$4, status=$5 WHERE org_id=$1',
    [orgId, next.name, next.domains, next.plan, next.status]);
  if (domains != null) await backfill(orgId);
}

// Users already signed up with the organization's domain join it
async function backfill(orgId) {
  const org = await get(orgId); if (!org || !org.domains) return 0;
  let n = 0;
  for (const d of org.domains.split(',').filter(Boolean)) {
    const r = await db().query(`UPDATE users SET org_id=$2, org_joined='domain' WHERE org_id IS NULL AND user_id NOT LIKE 'demo-%' AND lower(email) LIKE $1
      AND COALESCE(org_optout,'') <> $2`, [`%@${d}`, orgId]);
    n += r.rowCount || 0;
  }
  return n;
}

// Called at every user sign-in: join if your address was added by an organization, or by email domain
async function joinByDomain(user) {
  if (!user?.id || String(user.id).startsWith('demo-')) return null;
  const row = (await db().query('SELECT org_id, org_optout FROM users WHERE user_id=$1', [user.id])).rows[0];
  if (!row || row.org_id) return row?.org_id || null;
  const listed = (await db().query(`SELECT a.org_id FROM org_allowed_emails a JOIN organisations o ON o.org_id = a.org_id
    WHERE a.email = lower($1) AND o.status = 'active'`, [String(user.email || '')])).rows[0];
  if (listed && row.org_optout !== listed.org_id) {
    await db().query(`UPDATE users SET org_id=$2, org_joined='list' WHERE user_id=$1 AND org_id IS NULL`, [user.id, listed.org_id]);
    return listed.org_id;
  }
  const domain = String(user.email || '').split('@')[1]?.toLowerCase();
  if (!domain || FREE_MAIL.has(domain)) return null;
  const org = (await db().query(`SELECT * FROM organisations WHERE status='active' AND ',' || domains || ',' LIKE '%,' || $1 || ',%'`, [domain])).rows[0];
  if (!org || row.org_optout === org.org_id) return null;
  await db().query(`UPDATE users SET org_id=$2, org_joined='domain' WHERE user_id=$1 AND org_id IS NULL`, [user.id, org.org_id]);
  return org.org_id;
}

// ── Invite links ─────────────────────────────────────────────
async function createInvite(orgId, by, { days = 14, maxUses = 50 } = {}) {
  if (!await get(orgId)) throw new Error('Organization not found.');
  const code = crypto.randomBytes(12).toString('base64url');
  await db().query('INSERT INTO org_invites (code, org_id, created_by, expires_at, max_uses) VALUES ($1,$2,$3,NOW() + ($4 || \' days\')::interval,$5)',
    [code, orgId, by, String(Math.min(90, Math.max(1, days))), Math.min(1000, Math.max(1, maxUses))]);
  return code;
}
const invites = async (orgId) => (await db().query('SELECT * FROM org_invites WHERE org_id=$1 AND revoked=0 ORDER BY created_at DESC', [orgId])).rows;
const revokeInvite = (orgId, code) => db().query('UPDATE org_invites SET revoked=1 WHERE org_id=$1 AND code=$2', [orgId, code]);
async function joinByInvite(user, code) {
  if (!user?.id || String(user.id).startsWith('demo-')) throw new Error('The demo account can\'t join an organization.');
  const inv = (await db().query(`SELECT i.*, o.name, o.status FROM org_invites i JOIN organisations o ON o.org_id = i.org_id
    WHERE i.code=$1 AND i.revoked=0 AND (i.expires_at IS NULL OR i.expires_at > NOW()) AND i.uses < i.max_uses`, [String(code || '')])).rows[0];
  if (!inv || inv.status !== 'active') throw new Error('This invite link is not valid any more. Ask your organization for a new one.');
  const me = (await db().query('SELECT org_id FROM users WHERE user_id=$1', [user.id])).rows[0];
  if (me?.org_id === inv.org_id) return { orgId: inv.org_id, name: inv.name, already: true };
  if (me?.org_id) throw new Error('You already belong to another organization. Leave it in Settings first.');
  await db().query(`UPDATE users SET org_id=$2, org_joined='invite', org_optout=NULL WHERE user_id=$1`, [user.id, inv.org_id]);
  await db().query('UPDATE org_invites SET uses = uses + 1 WHERE code=$1', [inv.code]);
  return { orgId: inv.org_id, name: inv.name };
}
async function removeMember(orgId, userId) {
  const r = await db().query(`UPDATE users SET org_id=NULL, org_joined=NULL, org_optout=$2 WHERE user_id=$1 AND org_id=$2`, [userId, orgId]);
  // also take them off the organization's email list, so removing someone really removes them
  await db().query(`DELETE FROM org_allowed_emails WHERE org_id=$1 AND email = (SELECT lower(email) FROM users WHERE user_id=$2)`, [orgId, userId]);
  return r.rowCount > 0;
}

// ── Add people by email ──────────────────────────────────────
const EMAIL = /^[a-z0-9._%+'-]+@([a-z0-9-]+\.)+[a-z]{2,}$/;
async function addEmails(orgId, text, by) {
  const org = await get(orgId); if (!org) throw new Error('Organization not found.');
  const all = [...new Set(String(text || '').toLowerCase().split(/[\s,;]+/).map(e => e.replace(/^<|>$/g, '').trim()).filter(Boolean))];
  if (all.length > 500) throw new Error('Add up to 500 addresses at a time.');
  const out = { added: [], already: [], otherOrg: [], invalid: [], joinedNow: [] };
  for (const email of all) {
    if (!EMAIL.test(email) || email.endsWith('@demo.genjutsu')) { out.invalid.push(email); continue; }
    const have = (await db().query('SELECT org_id FROM org_allowed_emails WHERE email=$1', [email])).rows[0];
    if (have) { (have.org_id === orgId ? out.already : out.otherOrg).push(email); continue; }
    const member = (await db().query('SELECT org_id FROM users WHERE lower(email)=$1 AND org_id IS NOT NULL AND org_id <> $2', [email, orgId])).rows[0];
    if (member) { out.otherOrg.push(email); continue; }
    await db().query('INSERT INTO org_allowed_emails (email, org_id, added_by) VALUES ($1,$2,$3)', [email, orgId, by]);
    out.added.push(email);
    // already using Genjutsu? join now (unless they left this organization before; they can rejoin with a link)
    const j = await db().query(`UPDATE users SET org_id=$2, org_joined='list', org_optout=NULL WHERE lower(email)=$1 AND org_id IS NULL
      AND user_id NOT LIKE 'demo-%' RETURNING user_id`, [email, orgId]);
    if (j.rowCount) out.joinedNow.push(email);
  }
  return out;
}
const allowedEmails = async (orgId) => (await db().query(`SELECT a.email, a.added_by, a.added_at,
    (SELECT u.org_id = a.org_id FROM users u WHERE lower(u.email) = a.email LIMIT 1) AS joined
  FROM org_allowed_emails a WHERE a.org_id=$1 ORDER BY a.added_at DESC, a.email`, [orgId])).rows;
const removeEmail = (orgId, email) => db().query('DELETE FROM org_allowed_emails WHERE org_id=$1 AND email=$2', [orgId, String(email || '').toLowerCase()]);
async function forUser(userId) {
  return (await db().query(`SELECT o.org_id, o.name, o.plan, o.status, u.org_joined FROM users u JOIN organisations o ON o.org_id = u.org_id WHERE u.user_id=$1`, [userId])).rows[0] || null;
}

module.exports = { initOrgs, isOrgId, PLANS, list, get, create, update, backfill, joinByDomain, seatsUsed,
  createInvite, invites, revokeInvite, joinByInvite, removeMember, forUser, cleanDomains, addEmails, allowedEmails, removeEmail };
