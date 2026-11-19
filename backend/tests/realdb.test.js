// Runs only when TEST_DATABASE_URL points at an EMPTY throwaway Postgres database (GitHub starts one).
// It creates tables and fake users there, so never point it at the real database.
process.env.DATABASE_URL = process.env.TEST_DATABASE_URL;
process.env.SESSION_SECRET = 'x'; process.env.GROQ_API_KEY = ''; process.env.SAFE_BROWSING_API_KEY = '';
const { test } = require('node:test');
const assert = require('assert');
const path = require('path'); const R = (p) => require(path.join(__dirname, '..', p));
const db = R('database/db'); const adb = R('database/adminDb'); const trainer = R('services/modelTrainer');
const { analyseEmail } = R('services/threatService');
const PASS = (d) => `spf=pass smtp.mailfrom=${d}; dkim=pass header.i=@${d}; dmarc=pass header.from=${d}`;
test('real database: every number counted correctly, demo data hidden', { skip: !process.env.TEST_DATABASE_URL && 'set TEST_DATABASE_URL to an empty Postgres database to run this' }, async () => {
  await db.initDB(); await adb.initAdminDb(); await trainer.initTrainingDb();
  await R('services/sharedFeed').initSharedFeed(); await R('services/attachmentScanner').initAttachmentDb(); await R('services/orgs').initOrgs();
  const U = 'u-real', D = 'demo-abc';
  await db.query(`INSERT INTO users (user_id,email,username) VALUES ($1,'prince@x.com','Prince Magar'),($2,'demo-abc@demo.genjutsu','Demo user')`, [U, D]);
  const now = new Date().toUTCString();
  const mails = [
    { id: 'p1', from: 'PayPal <alerts@paypa1-verify.co>', subject: 'Verify your account', body: 'Verify your account now http://paypa1-verify.co/login', links: ['http://paypa1-verify.co/login'] },
    { id: 'p2', from: 'Nabil <a@nabil-notify.info>', subject: 'e-statement', body: 'x', html: '<a href="http://login-secure.xyz/n">www.nabilbank.com</a>', links: ['http://login-secure.xyz/n'] },
    { id: 'p3', from: 'HR <hr@payroll-docs.biz>', subject: 'Salary', body: 'open the file', attachments: [{ filename: 'salary.pdf.exe' }] },
    { id: 'p4', from: 'Accounts <billing@acme-supplies.com>', replyTo: 'acme.billing@gmail.com', subject: 'Bank details', body: 'Please note our change of bank details', authResults: PASS('acme-supplies.com') },
    { id: 'm1', from: 'College <registrar@college.edu.np>', subject: 'act now urgent', body: 'urgent verify your account act now limited time', links: ['http://203.0.113.9/x'] },
    { id: 's1', from: 'Neon <product@email.neon.tech>', subject: 'Welcome', body: 'hello there newsletter', authResults: PASS('email.neon.tech'), listUnsubscribe: '<x>' },
    { id: 's2', from: 'Friend <a@gmail.com>', subject: 'lunch', body: 'lunch friday?', authResults: PASS('gmail.com') },
    { id: 's3', from: 'Google <no-reply@accounts.google.com>', subject: 'Security alert', body: 'New sign-in', authResults: PASS('accounts.google.com') },
  ];
  for (const m of mails) {
    const e = { links: [], attachments: [], date: now, ...m };
    await db.saveEmailScan(e, await analyseEmail(e, { domainAge: false }), U);
  }
  // scan p1 a second time (rescans must not double count)
  { const e = { links: [], attachments: [], date: now, ...mails[0] }; await db.saveEmailScan(e, await analyseEmail(e, { domainAge: false }), U); }
  // quarantine p1, p3; user marks m1 safe
  await db.blockEmail(U, `${U}-p1`, 'p1', '', '', 'auto'); await db.blockEmail(U, `${U}-p3`, 'p3', '', '', 'auto');
  const m1level = (await db.query(`SELECT threat_type FROM scan_results WHERE email_id=$1`, [`${U}-m1`])).rows[0].threat_type;
  await db.userOverrideThreatLevel(`${U}-m1`, 'safe', U, 'This is my college');
  // demo user: 2 threats + honeypot chat that must not show anywhere
  for (const m of mails.slice(0, 2)) { const e = { links: [], attachments: [], date: now, ...m }; await db.saveEmailScan(e, await analyseEmail(e, { domainAge: false }), D); }
  await db.query(`INSERT INTO honeypot_sessions (session_id,user_id,sender_email,status) VALUES ('hpdemo',$1,'x@y.z','active')`, [D]);

  const levels = {}; for (const r of await db.getUserThreatRecords(U, 30)) levels[r.gmail_message_id] = r.override_level || r.threat_type;
  console.log('levels', levels, 'm1 was', m1level);

  // ── user Threats page ──
  const { recordToEmail } = R('services/threatRecords');
  const all = (await db.getUserThreatRecords(U, 90)).map(recordToEmail);
  const threats = all.filter(e => ['dangerous', 'suspicious'].includes(e.threat.level));
  console.log('user: scanned', all.length, 'threats', threats.length, 'quarantined', threats.filter(e => e.quarantined).length,
    'types', threats.reduce((t, e) => (t[e.threat.subType] = (t[e.threat.subType] || 0) + 1, t), {}));
  assert.equal(all.length, 8, 'each email once, rescans not double counted');
  assert.ok(!threats.find(e => e.id === 'm1'), 'user-marked-safe email is not a threat');
  assert.equal(threats.filter(e => e.quarantined).length, 2, 'quarantined threats still counted');
  assert.equal(threats.find(e => e.id === 'p1')?.quarantined, true);
  const m1 = all.find(e => e.id === 'm1'); assert.equal(m1.adminRemark, 'This is my college'); assert.equal(m1.threat.level, 'safe');

  // ── admin numbers ──
  const S = await adb.systemStats(); console.log('admin stats', S);
  assert.deepEqual(S.subtypes, { phishing: 2, malware_link: 1, spoofed_sender: 1, other: 0 }, 'each threat on the right card');
  assert.equal(S.totalUsers, 1, 'demo user not counted'); assert.equal(S.totalEmails, 8);
  assert.equal(S.totalHoneypot, 0, 'demo honeypot not counted'); assert.equal(S.activeHoneypot, 0);
  assert.equal(S.totalThreats, threats.length);
  assert.equal(Object.values(S.subtypes).reduce((a, b) => a + b, 0), threats.length);
  const c = await adb.counts24h(); console.log('24h', c); assert.equal(c.scanned, 8); assert.equal(c.dangerous + c.suspicious, threats.length);
  const t = await adb.trend(7); console.log('trend', t); assert.equal(t.threats.at(-1) + t.safe.at(-1), 8); assert.equal(t.threats.at(-1), threats.length);
  const feed = await adb.liveFeed(50); assert.ok(feed.every(f => f.user_email === 'prince@x.com')); assert.equal(feed.length, threats.length);
  const att = await adb.topAttackers(7, 20); console.log('attackers', att.map(a => `${a.domain}:${a.users}`));
  assert.ok(att.every(a => a.users === 1), 'demo user not counted as a victim');
  const mis = await adb.mistakes(); console.log('mistakes', mis.map(m => m.subject)); assert.equal(mis.length, 1);
  await adb.hourly(); await adb.origins(7); await adb.health(); await adb.attackerDetail('paypa1-verify.co'); await adb.userList(); await adb.userDetail(U); await adb.problemUsers();
  const mr = await adb.monthReport(new Date().getUTCFullYear(), new Date().getUTCMonth() + 1); console.log('month', mr.totals, 'quarantined', mr.quarantined, 'hp', mr.honeypot);
  assert.equal(mr.totals.users, 1); assert.equal(mr.honeypot.sessions, 0); assert.equal(mr.quarantined, 2);
  // training collection works on real SQL too
  console.log('collected', await trainer.collect());

  // ── Every page over HTTP ─────────────────────────────────
  const express = require('express'); const mail = R('services/mail');
  mail.fetchEmails = async () => [];      // no real mailbox here; pages must still show the saved numbers
  const core = R('admin/adminCore');
  let who = 'user';
  const app = express(); app.use(express.json());
  app.use((rq, rs, next) => { rq.session = who === 'user' ? { user: { id: U, email: 'prince@x.com', name: 'Prince Magar', provider: 'google' } }
    : { admin: core.sessionFor({ admin_id: 's1', email: 'boss@x.com', role: 'superadmin' }) }; next(); });
  for (const r of ['threats', 'analytics', 'honeypot', 'settings', 'account', 'emails', 'notifications']) app.use('/api', R('routes/' + r));
  app.use('/admin/api', R('admin/adminRoutes'));
  const srv = await new Promise(r => { const s = app.listen(0, () => r(s)); });
  srv.unref();   // a failed check must not keep the test running forever
  const base = `http://127.0.0.1:${srv.address().port}`;
  const get = async (p) => { const r = await fetch(base + p); const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = null; }
    if (r.status !== 200 || (j && j.success === false)) throw new Error(`${p} -> ${r.status} ${t.slice(0, 200)}`); return j || t; };
  const th = await get('/api/threats'); console.log('GET /api/threats', th.summary);
  assert.equal(th.summary.total, 4); assert.equal(th.summary.quarantined, 2); assert.equal(th.summary.scanned, 8);
  const dash = await get('/api/analytics/dashboard'); console.log('GET /api/analytics/dashboard', dash.stats, dash.threatSubtypes, dash.charts.types);
  assert.equal(dash.stats.totalEmails, 8); assert.equal(dash.stats.dangerous + dash.stats.suspiciousEmails, 4); assert.equal(dash.stats.quarantined, 2);
  assert.equal(dash.charts.trend.data.at(-1) + dash.charts.trend.safe.at(-1), 8);
  assert.ok(!dash.charts.types.labels.some(l => /newsletter|known sender/i.test(l)), 'safe reasons are not threat types');
  for (const p of ['/api/analytics/insights', '/api/honeypot/sessions', '/api/honeypot/intel', '/api/threats/summary', '/api/emails/blocked', '/api/account/activity', '/api/account/rules', '/api/announcements', '/api/account/api-keys', '/api/settings'])
    { await get(p); console.log('GET', p, 'ok'); }
  const hp = await get('/api/honeypot/sessions'); assert.equal((hp.sessions || []).length, 0, 'real user has no honeypot chats');
  who = 'admin';
  for (const p of ['/stats', '/trend?days=7', '/wall', '/queue', '/blocked', '/honeypot/sessions', '/attackers?days=7', '/attackers/paypa1-verify.co', '/users/list', `/users/${U}/detail`,
                   '/mistakes', '/intel', '/model', '/health', '/blocklist', '/announcements', '/actions', '/admin-activity?limit=10', '/activity?limit=10', '/settings', '/admins', '/honeypot/leaderboard'])
    { const j = await get('/admin/api' + p); console.log('GET /admin/api' + p, 'ok'); }
  const ahp = await get('/admin/api/honeypot/sessions'); console.log('admin honeypot', ahp.stats); assert.equal(ahp.stats.total, 0, 'demo chat hidden from admin');
  const wall = await get('/admin/api/wall'); assert.ok(wall.feed.every(f => f.user_email === 'prince@x.com'));
  const blk = await get('/admin/api/blocked'); assert.equal(blk.summary.total, blk.blocked.filter(b => true).length); assert.ok(blk.blocked.every(b => b.userEmail === 'prince@x.com'));
  const q = await get('/admin/api/queue'); console.log('queue', q.items.map(i => i.type));
  const pdf = await fetch(base + '/admin/api/report/monthly'); assert.equal(pdf.headers.get('content-type'), 'application/pdf');
  const csv = await get('/admin/api/admin-activity.csv'); assert.ok(String(csv).startsWith('logged_at'));
  srv.close();
  console.log('\nALL REAL-DATABASE CHECKS PASSED');
  await db.pool.end();
});
