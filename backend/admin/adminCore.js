// admin/adminCore.js — roles, permissions and the checks every admin route uses
const PERMISSIONS = {
  superadmin: [
    'stats','users','threats','honeypot','export','settings','queue','attackers','health','reports',
    'review','notes','dismiss','activity','override_threat','blocklist','announce','mistakes','intel','request',
    'admins','ml_settings','admin_activity','suspend_user','approve'
  ],
  moderator: [
    'stats','users','threats','honeypot','export','settings','queue','attackers','health','reports',
    'review','notes','dismiss','activity','override_threat','blocklist','announce','mistakes','intel','request'
  ],
  viewer: ['stats','users','threats','honeypot','export','settings','queue','attackers','health','reports']
};
const ROLE_LABELS = { superadmin: 'Super Admin', moderator: 'Moderator', viewer: 'Viewer' };
const IDLE_MS = 30 * 60 * 1000;   // signed out after 30 minutes without activity
// Organization admins only ever get these (and only what their role already has). Everything else
// changes or shows things for every organization. 'organization' = their own organization's page.
const ORG_PERMS = ['stats', 'users', 'threats', 'honeypot', 'attackers', 'mistakes', 'announce'];
const { runWithOrg, orgAllowed } = require('./orgScope');
const { isOrgId } = require('../services/orgs');

function getIP(req) {
  return String(req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').split(',')[0].trim();
}

// Signed in, not idle for too long. Read-only mode blocks every change.
function requireAdmin(req, res, next) {
  const a = req.session?.admin;
  if (!a?.loggedIn) return res.status(403).json({ success: false, error: 'Admin access required.' });
  const now = Date.now();
  if (a.lastSeen && now - a.lastSeen > IDLE_MS) {
    req.session.admin = null;
    return res.status(401).json({ success: false, expired: true, error: 'Signed out after 30 minutes without activity. Please sign in again.' });
  }
  a.lastSeen = now;
  if (a.readOnly && req.method !== 'GET' && !READONLY_ALLOWED.some(p => req.path.startsWith(p)))
    return res.status(423).json({ success: false, readOnly: true, error: 'Read-only mode is on. Turn it off to make changes.' });
  if (a.orgId && !orgAllowed(req.method, req.path))
    return res.status(403).json({ success: false, orgOnly: true, error: 'Organization admins can only see their own organization.' });
  let view = a.orgId || null;
  if (!a.orgId && a.role === 'superadmin') {
    const pick = req.get('x-genjutsu-org');
    if (pick) { if (!isOrgId(pick)) return res.status(400).json({ success: false, error: 'Unknown organization.' }); view = pick; }
  }
  runWithOrg(view, next);
}
const READONLY_ALLOWED = ['/logout', '/me/readonly'];

function can(permission) {
  return (req, res, next) => {
    const a = req.session?.admin, role = a?.role || 'viewer';
    if (permsOf(a).includes(permission)) return next();
    res.status(403).json({ success: false, error: `Your role (${ROLE_LABELS[role] || role}) cannot do this.`, role, required: permission });
  };
}

// What an admin may do: their role's list, minus everything-wide powers for organization admins.
// 'org' = manage their organization's invites and members; 'orgs' = create and edit organizations (Super Admin).
function permsOf(a) {
  const role = a?.role || 'viewer';
  const base = PERMISSIONS[role] || [];
  if (role === 'superadmin') return [...base, 'orgs', 'org'];
  if (!a?.orgId) return base;
  return [...base.filter(p => ORG_PERMS.includes(p)), 'organization', ...(role === 'moderator' ? ['org'] : [])];
}
function sessionFor(admin) {
  const orgId = admin.role === 'superadmin' ? null : (admin.org_id || null);   // a Super Admin is never tied to one organization
  return {
    orgId, orgName: admin.org_name || null,
    loggedIn: true, adminId: admin.admin_id, email: admin.email,
    name: admin.name || admin.email, role: admin.role,
    roleLabel: ROLE_LABELS[admin.role] || admin.role,
    permissions: permsOf({ role: admin.role, orgId }),
    isSuperAdmin: admin.role === 'superadmin',
    twoFactor: !!admin.totp_enabled,
    readOnly: false,
    lastSeen: Date.now(),
  };
}

const csvCell = (v) => { const s = v == null ? '' : (v instanceof Date ? v.toISOString() : String(v)); return /[",\n\r]/.test(s) || /^[=+\-@]/.test(s) ? `"${s.replace(/^([=+\-@])/, "'$1").replace(/"/g, '""')}"` : s; };
const toCsv = (rows, cols) => [cols.join(','), ...rows.map(r => cols.map(c => csvCell(r[c])).join(','))].join('\n') + '\n';

module.exports = { permsOf, ORG_PERMS, PERMISSIONS, ROLE_LABELS, IDLE_MS, getIP, requireAdmin, can, sessionFor, toCsv };
