// admin/orgScope.js — keeps each organization's admins inside their own organization.
//
// 1. Every admin request runs inside a small "context" that remembers the admin's organization.
//    The data layer asks realUser() for its "real accounts" filter, and for an organization admin that
//    filter also says "and only users of this organization". One place, so no query can forget it.
// 2. Deny by default: an organization admin can only open the pages listed in ORG_ALLOWED. Anything
//    else (global block list, model, other admins, settings, …) answers 403, so a page that was
//    never limited to one organization can't leak another organization's data.
const { AsyncLocalStorage } = require('async_hooks');
const { isOrgId } = require('../services/orgs');
const als = new AsyncLocalStorage();

const currentOrg = () => als.getStore()?.orgId || null;
function realUser(col = 'e.user_id') {
  const org = currentOrg();
  const base = `${col} NOT LIKE 'demo-%'`;
  if (!org) return base;
  if (!isOrgId(org)) throw new Error('Bad organization id');   // strict format check, so it is safe to put in SQL
  return `${base} AND ${col} IN (SELECT user_id FROM users WHERE org_id = '${org}')`;
}
function runWithOrg(orgId, fn) { return als.run({ orgId: orgId || null }, fn); }

const ORG_ALLOWED = [
  ['GET',    /^\/me(\/security)?$/],
  ['POST',   /^\/(logout|me\/password|me\/readonly|me\/2fa\/(setup|enable|disable))$/],
  ['GET',    /^\/(stats|trend|wall|blocked|attackers|mistakes|users\/list|honeypot\/sessions|honeypot\/leaderboard|announcements|org)$/],
  ['GET',    /^\/users\/[^/]+\/detail$/],
  ['GET',    /^\/attackers\/[^/]+$/],
  ['GET',    /^\/honeypot\/sessions\/[^/]+\/messages$/],
  ['POST',   /^\/announcements$/],
  ['DELETE', /^\/announcements\/[^/]+$/],
  ['POST',   /^\/org\/(invites|allowed)$/],
  ['DELETE', /^\/org\/allowed\/[^/]+$/],
  ['DELETE', /^\/org\/invites\/[^/]+$/],
  ['POST',   /^\/org\/members\/[^/]+\/remove$/],
];
const orgAllowed = (method, path) => ORG_ALLOWED.some(([m, re]) => m === method && re.test(path));

// Does this user belong to the current admin's organization? (always true for the Super Admin)
async function userInScope(userId) {
  const org = currentOrg(); if (!org) return true;
  const { query } = require('../database/db');
  return (await query('SELECT 1 FROM users WHERE user_id=$1 AND org_id=$2', [String(userId), org])).rows.length > 0;
}
async function scopedUserIds() {
  const org = currentOrg(); if (!org) return null;
  const { query } = require('../database/db');
  return new Set((await query('SELECT user_id FROM users WHERE org_id=$1', [org])).rows.map(r => r.user_id));
}

// The Genjutsu team can look at one organization with ?org=ID (same filters an organization admin gets)
function viewOrg(req, res, next) {
  const a = req.session?.admin, o = req.query.org;
  if (a && !a.orgId && o != null) {
    if (!isOrgId(o)) return res.status(400).json({ success: false, error: 'Unknown organization.' });
    return runWithOrg(o, next);
  }
  next();
}

module.exports = { viewOrg, als, currentOrg, realUser, runWithOrg, orgAllowed, ORG_ALLOWED, userInScope, scopedUserIds };
