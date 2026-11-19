// Real database: two organizations. Organization A's admin must never see anything from B.
// Also checks joining (no member limit), the shared feed, the attachment cache and the one-time re-check.
// Runs only with TEST_DATABASE_URL pointing at a throwaway Postgres server. It makes its own
// separate database (<name>_orgs) next to it, so it never mixes with realdb.test.js.
process.env.SESSION_SECRET = 'x'; process.env.GROQ_API_KEY = ''; process.env.SAFE_BROWSING_API_KEY = '';
const { test } = require('node:test');
const assert = require('assert');
const express = require('express');
const path = require('path'); const R = (p) => require(path.join(__dirname, '..', p));
const { files } = require('./_files');

test('real database: organizations are kept apart', { skip: !process.env.TEST_DATABASE_URL && 'set TEST_DATABASE_URL to an empty Postgres database to run this' }, async () => {
  const { Client } = require('pg');
  const url = new URL(process.env.TEST_DATABASE_URL);
  const name = url.pathname.slice(1) + '_orgs';
  if (!/^[a-z0-9_]+$/i.test(name)) throw new Error('unexpected database name');
  const admin = new Client({ connectionString: process.env.TEST_DATABASE_URL }); await admin.connect();
  await admin.query(`DROP DATABASE IF EXISTS ${name}`); await admin.query(`CREATE DATABASE ${name}`); await admin.end();
  url.pathname = '/' + name; process.env.DATABASE_URL = url.toString();
  const db = R('database/db'); const adb = R('database/adminDb');
  const orgs = R('services/orgs'); const core = R('admin/adminCore');
  const { analyseEmail } = R('services/threatService');
  await db.initDB(); await adb.initAdminDb(); await R('services/modelTrainer').initTrainingDb();
  await R('services/sharedFeed').initSharedFeed(); await R('services/attachmentScanner').initAttachmentDb(); await orgs.initOrgs();
  // Tables can be created twice without errors (every server start does this)
  await orgs.initOrgs(); await R('services/attachmentScanner').initAttachmentDb();

  // ── Schools and joining ──
  const A = await orgs.create({ name: 'Alpha School', domains: 'alpha.edu.np', plan: 'free', by: 'boss' });
  const B = await orgs.create({ name: 'Beta College', domains: 'beta.edu.np', plan: 'school', by: 'boss' });
  await assert.rejects(orgs.create({ name: 'Copy', domains: 'alpha.edu.np' }), /already belongs/);
  const users = [['a1', 'ram@alpha.edu.np'], ['a2', 'sita@alpha.edu.np'], ['b1', 'hari@beta.edu.np'], ['b2', 'gita@beta.edu.np'], ['x1', 'loner@gmail.com'], ['demo-z', 'demo@alpha.edu.np']];
  for (const [id, email] of users) { await db.query('INSERT INTO users (user_id,email,username) VALUES ($1,$2,$3)', [id, email, email.split('@')[0]]); await orgs.joinByDomain({ id, email }); }
  const orgOf = async (id) => (await db.query('SELECT org_id FROM users WHERE user_id=$1', [id])).rows[0].org_id;
  assert.equal(await orgOf('a1'), A); assert.equal(await orgOf('b2'), B);
  assert.equal(await orgOf('x1'), null, 'gmail never joins'); assert.equal(await orgOf('demo-z'), null, 'demo never joins');

  // invite: the gmail user joins A with a link; a new staff member joins by domain
  const code = await orgs.createInvite(A, 'it@alpha', { days: 7, maxUses: 5 });
  assert.equal((await orgs.joinByInvite({ id: 'x1' }, code)).orgId, A);
  await db.query(`INSERT INTO users (user_id,email) VALUES ('a3','new@alpha.edu.np')`);
  assert.equal(await orgs.joinByDomain({ id: 'a3', email: 'new@alpha.edu.np' }), A);
  await assert.rejects(orgs.joinByInvite({ id: 'b1' }, code), /another organization/);
  await assert.rejects(orgs.joinByInvite({ id: 'a3' }, 'not-a-real-code'), /not valid/);
  // removed people don't come straight back by domain
  assert.ok(await orgs.removeMember(A, 'a2'));
  assert.equal(await orgs.joinByDomain({ id: 'a2', email: 'sita@alpha.edu.np' }), null);
  // stopped link: refused
  await orgs.revokeInvite(A, code); await assert.rejects(orgs.joinByInvite({ id: 'a2' }, code), /not valid/);
  // no member limit: 500 more people with the domain all join (backfill), the opted-out one stays out
  await db.query(`INSERT INTO users (user_id,email) SELECT 'bulk-' || g, 'p' || g || '@alpha.edu.np' FROM generate_series(1,500) g`);
  assert.equal(await orgs.backfill(A), 500);
  assert.equal(await orgs.seatsUsed(A), 503);
  assert.equal(await orgOf('a2'), null, 'opted out: backfill leaves them out');
  await db.query(`DELETE FROM users WHERE user_id LIKE 'bulk-%'`);
  // the old plan name still works and is saved as "paid"
  assert.equal((await orgs.get(B)).plan, 'paid');

  // ── Added by email (organizations without their own domain) ──
  await db.query(`INSERT INTO users (user_id,email) VALUES ('g1','Already.Here@gmail.com')`);
  const r1 = await orgs.addEmails(A, 'already.here@gmail.com, new.person@gmail.com\nnot-an-email; hari@beta.edu.np new.person@gmail.com', 'it@alpha');
  assert.deepEqual(r1.added.sort(), ['already.here@gmail.com', 'new.person@gmail.com']);
  assert.deepEqual(r1.joinedNow, ['already.here@gmail.com'], 'an existing user joins straight away');
  assert.deepEqual(r1.invalid, ['not-an-email']); assert.deepEqual(r1.otherOrg, ['hari@beta.edu.np'], 'a member of B is not taken over');
  assert.equal(await orgOf('g1'), A);
  // someone on the list signs up later → joins at sign-in
  await db.query(`INSERT INTO users (user_id,email) VALUES ('g2','new.person@gmail.com')`);
  assert.equal(await orgs.joinByDomain({ id: 'g2', email: 'new.person@gmail.com' }), A);
  assert.equal((await orgs.addEmails(B, 'new.person@gmail.com', 'it@beta')).otherOrg.length, 1, 'one organization per address');
  // removing a member also takes them off the list, so they don't come back
  assert.ok(await orgs.removeMember(A, 'g2'));
  assert.ok(!(await orgs.allowedEmails(A)).some(a => a.email === 'new.person@gmail.com'));
  assert.equal(await orgs.joinByDomain({ id: 'g2', email: 'new.person@gmail.com' }), null);
  assert.equal((await orgs.allowedEmails(A)).find(a => a.email === 'already.here@gmail.com').joined, true);
  await orgs.removeMember(A, 'g1');   // keep the numbers below as they were

  // ── Mail for each school ──
  const now = new Date().toUTCString();
  const mail = (id, from, subject, extra = {}) => ({ id, from, subject, body: 'Verify your account now', links: [], attachments: [], date: now, ...extra });
  const save = async (u, e) => db.saveEmailScan(e, await analyseEmail(e, { domainAge: false }), u);
  await save('a1', mail('m1', 'PayPal <a@paypa1-verify.co>', 'ALPHA-SECRET-SUBJECT', { links: ['http://paypa1-verify.co/login'] }));
  await save('b1', mail('m2', 'Nabil <n@nabil-alerts.top>', 'BETA-SECRET-SUBJECT', { links: ['http://nabil-alerts.top/login'] }));
  await save('b2', mail('m3', 'Nabil <n@nabil-alerts.top>', 'BETA-SECOND', { links: ['http://nabil-alerts.top/login'] }));
  await db.query(`INSERT INTO honeypot_sessions (session_id,user_id,sender_email,subject,status) VALUES ('hpA','a1','s@x.co','ALPHA-CHAT','active'),('hpB','b1','s@y.co','BETA-CHAT','active')`);
  await db.userOverrideThreatLevel('b1-m2', 'safe', 'b1', 'not spam');

  // ── Admin portal as each kind of admin ──
  let who;
  const app = express(); app.use(express.json());
  app.use((rq, rs, next) => { rq.session = who; next(); });
  app.use('/admin/api', R('admin/adminRoutes'));
  const srv = await new Promise(r => { const s = app.listen(0, () => r(s)); }); srv.unref();
  const base = `http://127.0.0.1:${srv.address().port}/admin/api`;
  const as = (row) => ({ admin: core.sessionFor(row) });
  const call = async (p, method = 'GET', body) => {
    const r = await fetch(base + p, { method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    return { status: r.status, text: await r.text() };
  };
  try {
    who = as({ admin_id: 'sa', email: 'it@alpha.edu.np', role: 'moderator', org_id: A, org_name: 'Alpha School' });
    const pages = ['/stats', '/trend?days=7', '/wall', '/blocked', '/attackers?days=7', '/attackers/nabil-alerts.top', '/mistakes', '/users/list',
                   '/honeypot/sessions', '/honeypot/leaderboard', '/announcements', `/org?org=${B}`, '/users/a1/detail'];
    for (const p of pages) {
      const r = await call(p);
      assert.equal(r.status, 200, `${p}: ${r.text.slice(0, 200)}`);
      for (const leak of ['BETA', 'hari@', 'gita@', B, 'Beta College']) assert.ok(!r.text.includes(leak), `${p} shows "${leak}"`);
    }
    assert.ok((await call('/blocked')).text.includes('ALPHA-SECRET-SUBJECT'), 'own school is visible');
    assert.ok((await call('/honeypot/sessions')).text.includes('ALPHA-CHAT'));
    const st = JSON.parse((await call('/stats')).text).stats; assert.equal(st.totalUsers, 3); assert.equal(st.totalHoneypot, 1);
    assert.equal((await call('/users/b1/detail')).status, 404);
    assert.equal((await call('/users/a1/emails')).status, 403, 'organization admins never get the full list');
    assert.equal((await call('/honeypot/sessions/hpB/messages')).status, 404);
    assert.equal((await call('/org/members/b1/remove', 'POST', { org: B })).status, 404);
    assert.equal((await call('/org/allowed', 'POST', { org: B, emails: 'sneaky@gmail.com' })).status, 200);
    assert.equal((await db.query(`SELECT org_id FROM org_allowed_emails WHERE email='sneaky@gmail.com'`)).rows[0].org_id, A, 'added to their own organization, never B');
    await call('/org/allowed/sneaky@gmail.com', 'DELETE');
    assert.equal(await orgOf('b1'), B, 'B member untouched');
    // notices: A's notice reaches A's staff only
    assert.equal((await call('/announcements', 'POST', { message: 'Alpha staff: exams Monday' })).status, 200);
    assert.equal((await adb.activeAnnouncements('a1')).length, 1);
    assert.equal((await adb.activeAnnouncements('b1')).length, 0);
    for (const p of ['/blocklist', '/model', '/health', '/queue', '/admins', '/orgs', '/settings', '/shared-feed', '/report/monthly'])
      assert.equal((await call(p)).status, 403, p);

    // Super Admin sees both schools
    who = as({ admin_id: 'boss', email: 'boss@genjutsu', role: 'superadmin' });
    const all = await call('/blocked'); assert.ok(all.text.includes('ALPHA-SECRET') && all.text.includes('BETA-SECOND'));
    assert.equal(JSON.parse((await call('/orgs')).text).orgs.length, 2);
    const bo = JSON.parse((await call(`/org?org=${B}`)).text); assert.equal(bo.members.length, 2);
    // looking at one organization: only its people and threats
    const sb = JSON.parse((await call(`/stats?org=${B}`)).text).stats; assert.equal(sb.totalUsers, 2);
    const bb = await call(`/blocked?org=${B}`); assert.ok(bb.text.includes('BETA-SECOND') && !bb.text.includes('ALPHA'));
    const sa2 = JSON.parse((await call(`/stats?org=${A}`)).text).stats; assert.equal(sa2.totalUsers, 3);
    // a member's checked emails (team only)
    const me2 = JSON.parse((await call('/users/b2/emails')).text); assert.equal(me2.total, 1); assert.equal(me2.emails[0].subject, 'BETA-SECOND');
    assert.ok(me2.emails[0].reasons.length > 0);
    assert.equal((await call('/admins', 'POST', { email: 'it@beta.edu.np', password: 'BetaAdmin2026', role: 'viewer', orgId: B })).status, 200);
    const ba = await adb.getAdminFull('it@beta.edu.np'); assert.equal(ba.org_id, B); assert.equal(ba.org_name, 'Beta College');
    // pausing a school stops its admins signing in
    await call(`/orgs/${B}`, 'PUT', { status: 'suspended' });
    who = {};
    const login = await call('/login', 'POST', { email: 'it@beta.edu.np', password: 'BetaAdmin2026' });
    assert.equal(login.status, 403); assert.match(login.text, /paused/);
  } finally { srv.close(); }

  // ── Shared feed: one domain seen by two different users becomes active ──
  const feed = R('services/sharedFeed');
  const fr = await feed.rebuild();
  const nab = (await feed.list()).find(i => i.value === 'nabil-alerts.top');
  console.log('shared feed', fr, nab && { users: nab.users, status: nab.status });
  // b1 marked their copy safe, so only b2 counts → not active yet; paypa1 only one user
  assert.ok(!nab || nab.status !== 'active');

  // ── Attachment cache round trip (only results kept) ──
  const scanner = R('services/attachmentScanner');
  let downloads = 0;
  const em = [{ id: 'att1', attachments: [{ filename: 'invoice.docm', size: 900, attachmentId: 'q' }] }];
  await scanner.prepare({ id: 'a1', provider: 'google' }, em, { getAttachment: async () => { downloads++; return files.docmAutoMacro(); } });
  const again = [{ id: 'att1', attachments: [{ filename: 'invoice.docm', size: 900, attachmentId: 'q' }] }];
  await scanner.prepare({ id: 'a1', provider: 'google' }, again, { getAttachment: async () => { downloads++; return files.docmAutoMacro(); } });
  assert.equal(downloads, 1, 'second scan read from the cache');
  assert.ok(again[0].fileFindings[0].findings.some(f => f.level === 'dangerous'));
  const row = (await db.query('SELECT * FROM attachment_scans')).rows[0];
  assert.ok(!row.result.includes('AutoOpen') && /^[0-9a-f]{64}$/.test(row.sha256));

  // ── One-time re-check: runs once, then never again ──
  const tr = R('services/threatRecords');
  await db.query(`DELETE FROM system_settings WHERE key='subtype_rules_version'`);
  const first = await tr.reclassifyOnce(db.query); assert.ok(first && first.checked >= 3, JSON.stringify(first));
  assert.equal(await tr.reclassifyOnce(db.query), null);

  // ── Team alert settings ──
  const ta = R('services/teamAlerts');
  await assert.rejects(ta.setDiscord('https://evil.example/hook', 'boss'), /not a Discord webhook/);
  await ta.setDiscord('https://discord.com/api/webhooks/123/abc', 'boss');
  assert.equal((await ta.status()).discord, true);
  const stored = (await db.query(`SELECT value FROM system_settings WHERE key='team_discord_webhook'`)).rows[0].value;
  assert.ok(!stored.includes('discord.com'), 'webhook is stored sealed');

  console.log('\nALL ORGANIZATION CHECKS PASSED');
  await db.pool.end();
});
