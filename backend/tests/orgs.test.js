// Organizations: an organization's admin must never see another organization's data. These tests try to break that.
const { test } = require('node:test');
const assert = require('node:assert');
const { req } = require('./_setup');
const express = require('express');
const db = req('database/db');
const scope = req('admin/orgScope');
const core = req('admin/adminCore');
const orgs = req('services/orgs');

const MINE = 'org-aaaaaaaaaaaaaaaa', OTHER = 'org-bbbbbbbbbbbbbbbb';
let sqlLog = [];
// Every SQL statement the real code sends is captured here; answers are empty (or from `answer`)
let answer = () => ({ rows: [] });
db.pool.connect = async () => ({ query: async (t, p) => { sqlLog.push({ t, p }); return answer(t, p); }, release() {} });
Object.assign(db, { logActivity: async () => {} });

function app(admin) {
  const a = express(); a.use(express.json());
  const store = { admin: { loggedIn: true, lastSeen: Date.now(), ...admin } };
  a.use((rq, rs, next) => { rq.session = store; next(); });
  a.use('/admin/api', req('admin/adminRoutes'));
  return new Promise(r => { const s = a.listen(0, () => r({ s, url: `http://127.0.0.1:${s.address().port}/admin/api` })); });
}
const school = { adminId: 'a2', email: 'it@school.edu.np', role: 'moderator', orgId: MINE };
const call = (url, method = 'GET', body) => fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: body && method !== 'GET' ? JSON.stringify(body) : undefined });

test('the "real users" filter adds the organization for organization admins only', () => {
  assert.equal(scope.realUser(), `e.user_id NOT LIKE 'demo-%'`);
  scope.runWithOrg(MINE, () => assert.match(scope.realUser('u.user_id'), new RegExp(`u\\.user_id IN \\(SELECT user_id FROM users WHERE org_id = '${MINE}'\\)`)));
  assert.throws(() => scope.runWithOrg("org-x' OR '1'='1", () => scope.realUser()), /Bad organization id/);
});

test('organization admins are refused everything-wide pages (deny by default)', async () => {
  const { s, url } = await app(school);
  try {
    const refused = [
      ['GET', '/blocklist'], ['POST', '/blocklist'], ['DELETE', '/blocklist/evil.com'], ['GET', '/model'], ['POST', '/model/train'],
      ['GET', '/admins'], ['POST', '/admins'], ['GET', '/orgs'], ['POST', '/orgs'], ['PUT', `/orgs/${MINE}`],
      ['GET', '/settings'], ['PUT', '/settings'], ['GET', '/health'], ['GET', '/queue'], ['GET', '/threats'], ['GET', '/activity'],
      ['GET', '/admin-activity.csv'], ['GET', '/report/monthly'], ['GET', '/shared-feed'], ['GET', '/team-alerts'],
      ['POST', '/maintenance/reclassify'], ['GET', '/intel'], ['GET', '/intel.csv'], ['GET', '/actions'], ['POST', '/actions'],
      ['POST', '/users/u9/suspend'], ['DELETE', '/honeypot/sessions/hp1'], ['POST', '/threats/e1/override'], ['GET', '/users'],
    ];
    for (const [m, p] of refused) assert.ok([403, 404].includes((await call(url + p, m, {})).status), `${m} ${p}`);   // refused, or no such page
  } finally { s.close(); }
});

test('every query an organization admin triggers is limited to their organization', async () => {
  const { s, url } = await app(school);
  try {
    for (const p of ['/stats', '/trend', '/wall', '/attackers', '/attackers/evil.com', '/mistakes', '/users/list', '/honeypot/leaderboard', '/blocked']) {
      sqlLog = [];
      const r = await call(url + p);
      assert.notEqual(r.status, 403, p);
      const userData = sqlLog.filter(q => /FROM (emails|users|honeypot_sessions|alerts|threat_overrides|blocked_emails)\b/.test(q.t));
      assert.ok(userData.length, `${p} ran no user query`);
      for (const q of userData) assert.ok(q.t.includes(`org_id = '${MINE}'`), `${p} ran an unscoped query:\n${q.t.slice(0, 300)}`);
      assert.ok(!sqlLog.some(q => q.t.includes(OTHER)), p);
    }
  } finally { s.close(); }
});

test('guessing an id from another organization gets "not found"', async () => {
  const { s, url } = await app(school);
  answer = (t, p) => /SELECT 1 FROM users WHERE user_id=\$1 AND org_id=\$2/.test(t) ? { rows: p[1] === MINE && p[0] === 'mine-1' ? [{ 1: 1 }] : [] }
    : /FROM honeypot_sessions/.test(t) && /session_id/.test(t) ? { rows: [{ session_id: 'hp-x', user_id: 'stranger' }] } : { rows: [] };
  try {
    assert.equal((await call(`${url}/users/stranger/detail`)).status, 404);
    assert.equal((await call(`${url}/honeypot/sessions/hp-x/messages`)).status, 404);
    // ?org= and body.org are ignored for an organization admin: it always works on its own organization
    sqlLog = [];
    await call(`${url}/org?org=${OTHER}`);
    assert.ok(sqlLog.length && sqlLog.every(q => !JSON.stringify(q.p || []).includes(OTHER)));
    sqlLog = [];
    await call(`${url}/org/members/stranger/remove`, 'POST', { org: OTHER });
    assert.ok(sqlLog.some(q => /UPDATE users SET org_id=NULL/.test(q.t) && q.p.includes(MINE)) && !sqlLog.some(q => JSON.stringify(q.p || []).includes(OTHER)));
  } finally { s.close(); answer = () => ({ rows: [] }); }
});

test('organization viewers cannot manage members; a Super Admin is never limited', async () => {
  const v = await app({ ...school, role: 'viewer' });
  try {
    assert.equal((await call(`${v.url}/org/invites`, 'POST', {})).status, 403);
    assert.equal((await call(`${v.url}/announcements`, 'POST', { message: 'hello all' })).status, 403);
  } finally { v.s.close(); }
  // a superadmin row with an org_id still gets a session with no organization
  assert.equal(core.sessionFor({ admin_id: 'x', email: 'b@x', role: 'superadmin', org_id: MINE }).orgId, null);
  assert.ok(!core.sessionFor({ admin_id: 'y', email: 'm@x', role: 'moderator', org_id: MINE }).permissions.includes('blocklist'));
  const sa = await app({ adminId: 'a1', email: 'boss@x', role: 'superadmin' });
  try {
    sqlLog = []; await call(`${sa.url}/users/list`);
    assert.ok(sqlLog.length && sqlLog.every(q => !/org_id = 'org-/.test(q.t)));
  } finally { sa.s.close(); }
});

test('organization announcements go only to that organization', async () => {
  const { s, url } = await app(school);
  try {
    sqlLog = [];
    await call(`${url}/announcements`, 'POST', { message: 'Exams moved to Monday' });
    const ins = sqlLog.find(q => /INSERT INTO announcements/.test(q.t));
    assert.equal(ins.p.at(-1), MINE);
    sqlLog = [];
    await call(`${url}/announcements/ann-1`, 'DELETE');
    assert.ok(sqlLog.some(q => /UPDATE announcements SET active=0 WHERE announcement_id=\$1 AND org_id=\$2/.test(q.t) && q.p[1] === MINE));
  } finally { s.close(); }
});

test('domains: public email services can never be an organization domain', async () => {
  assert.deepEqual(orgs.cleanDomains(' @School.edu.np, school.edu.np;staff.school.edu.np '), ['school.edu.np', 'staff.school.edu.np']);
  assert.deepEqual(orgs.cleanDomains('it@school.edu.np'), ['school.edu.np']);
  await assert.rejects(orgs.create({ name: 'Bad', domains: 'princemagar338@gmail.com' }), /gmail\.com is a public email service/);
  return assert.rejects(orgs.create({ name: 'Bad', domains: 'gmail.com' }), /public email service/);
});
test('joining by domain: no member limit; free email and demo never join anything', async () => {
  answer = (t) => /SELECT org_id, org_optout FROM users/.test(t) ? { rows: [{ org_id: null, org_optout: null }] }
    : /FROM organisations WHERE status='active'/.test(t) ? { rows: [{ org_id: MINE }] }
    : /COUNT\(\*\)::int AS n FROM users WHERE org_id/.test(t) ? { rows: [{ n: 100000 }] } : { rows: [] };
  try {
    sqlLog = [];
    assert.equal(await orgs.joinByDomain({ id: 'g-1', email: 'staff@company.com.np' }), MINE, 'joins even with 100,000 members');
    assert.ok(sqlLog.some(q => /UPDATE users SET org_id/.test(q.t)));
    sqlLog = [];
    assert.equal(await orgs.joinByDomain({ id: 'g-2', email: 'someone@gmail.com' }), null);
    assert.ok(!sqlLog.some(q => /FROM organisations/.test(q.t)));
    assert.equal(await orgs.joinByDomain({ id: 'demo-1', email: 'x@company.com.np' }), null);
  } finally { answer = () => ({ rows: [] }); }
});

test('?org= lets the Genjutsu team look at one organization, but never moves an organization admin', async () => {
  const userData = () => sqlLog.filter(q => /FROM (emails|users|honeypot_sessions|alerts)\b/.test(q.t));
  const sa = await app({ adminId: 'a1', email: 'boss@x', role: 'superadmin' });
  try {
    for (const p of ['/blocked', '/stats', '/trend']) {
      sqlLog = []; const st = (await call(`${sa.url}${p}?org=${OTHER}`)).status; assert.ok(st !== 400 && st !== 403, p);   // fake db: empty answers
      assert.ok(userData().length && userData().every(q => q.t.includes(`org_id = '${OTHER}'`)), `${p} narrowed to OTHER`);
    }
    assert.equal((await call(`${sa.url}/blocked?org=x' OR 1=1--`)).status, 400);
  } finally { sa.s.close(); }
  const mine = await app(school);
  try {
    sqlLog = []; await call(`${mine.url}/blocked?org=${OTHER}`);
    assert.ok(userData().length && userData().every(q => q.t.includes(`org_id = '${MINE}'`) && !q.t.includes(OTHER)));
  } finally { mine.s.close(); }
});

test('organization portal header: the Super Admin views one organization; an organization admin cannot jump to another', async () => {
  const hdr = (url, org) => fetch(url, { headers: { 'X-Genjutsu-Org': org } });
  const userData = () => sqlLog.filter(q => /FROM (emails|users)\b/.test(q.t));
  const sa = await app({ adminId: 'a1', email: 'boss@x', role: 'superadmin' });
  try {
    sqlLog = []; await hdr(`${sa.url}/blocked`, OTHER);
    assert.ok(userData().length && userData().every(q => q.t.includes(`org_id = '${OTHER}'`)));
    assert.equal((await hdr(`${sa.url}/blocked`, "x' OR 1=1")).status, 400);
    sqlLog = []; await fetch(`${sa.url}/announcements`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Genjutsu-Org': OTHER }, body: JSON.stringify({ message: 'For OTHER only' }) });
    assert.equal(sqlLog.find(q => /INSERT INTO announcements/.test(q.t)).p.at(-1), OTHER, 'notice goes to the viewed organization');
  } finally { sa.s.close(); }
  const mine = await app(school);
  try {
    sqlLog = []; await hdr(`${mine.url}/blocked`, OTHER);
    assert.ok(userData().length && userData().every(q => q.t.includes(`org_id = '${MINE}'`) && !q.t.includes(OTHER)));
  } finally { mine.s.close(); }
});

test("a member's full email list is for the Genjutsu team only", async () => {
  answer = (t) => /SELECT user_id, email FROM users WHERE user_id=\$1/.test(t) ? { rows: [{ user_id: 'u1', email: 'ram@x.np' }] }
    : /FROM emails e/.test(t) && /e.user_id = \$1/.test(t) ? { rows: [{ email_id: 'e1', sender_email: 'a@b.co', subject: 'Hi', received_date: 'Tue, 18 Nov 2026 10:00:00 +0000', score: 12, threat_type: 'safe', details: '[]' },
      { email_id: 'e2', sender_email: 'x@scam.top', subject: 'Verify', score: 90, threat_type: 'dangerous', details: '["Look-alike link"]', quarantined: true }] } : { rows: [] };
  const sa = await app({ adminId: 'a1', email: 'boss@x', role: 'superadmin' });
  const mine = await app(school);
  try {
    const d = await (await call(`${sa.url}/users/u1/emails`)).json();
    assert.equal(d.total, 2); assert.deepEqual(d.counts, { dangerous: 1, suspicious: 0, safe: 1 });
    assert.deepEqual(d.emails[1].reasons, ['Look-alike link']);
    assert.ok(!JSON.stringify(d).includes('body'), 'message text is never sent');
    assert.ok(!sqlLog.some(q => /body_text/.test(q.t)), 'message text is never even read');
    assert.equal((await call(`${mine.url}/users/u1/emails`)).status, 403);
  } finally { sa.s.close(); mine.s.close(); answer = () => ({ rows: [] }); }
});

test('adding people by email: organization admins only, own organization only', async () => {
  const v = await app({ ...school, role: 'viewer' });
  try { assert.equal((await call(`${v.url}/org/allowed`, 'POST', { emails: 'a@gmail.com' })).status, 403); } finally { v.s.close(); }
  const mine = await app(school);
  try {
    sqlLog = []; await call(`${mine.url}/org/allowed`, 'POST', { org: OTHER, emails: 'a@gmail.com' });
    const ins = sqlLog.find(q => /INSERT INTO org_allowed_emails/.test(q.t));
    assert.ok(!ins || ins.p[1] === MINE); assert.ok(!sqlLog.some(q => JSON.stringify(q.p || []).includes(OTHER)));
  } finally { mine.s.close(); }
});
