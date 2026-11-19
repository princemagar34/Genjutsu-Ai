// Admin portal: sign-in security, approvals, block list, exports
const { test } = require('node:test');
const assert = require('node:assert');
const { req } = require('./_setup');
const express = require('express');
const auth = req('admin/adminAuth');
const core = req('admin/adminCore');
const db = req('database/db'); const adb = req('database/adminDb');
const { seal } = req('services/mail/secretBox');

test('passwords are hashed, rules enforced, old plain text still verifies once', () => {
  const h = auth.hashPassword('Kathmandu2026');
  assert.ok(h.startsWith('scrypt$') && !h.includes('Kathmandu'));
  assert.ok(auth.verifyPassword('Kathmandu2026', h)); assert.ok(!auth.verifyPassword('kathmandu2026', h));
  assert.ok(auth.verifyPassword('legacy', 'legacy'));
  assert.ok(auth.passwordProblem('short1')); assert.ok(auth.passwordProblem('onlyletterslong')); assert.equal(auth.passwordProblem('Kathmandu2026'), null);
});
test('2-step codes: RFC 6238 vector, clock drift, wrong codes', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';   // "12345678901234567890"
  assert.equal(auth.totpAt(secret, 1), '287082');
  assert.equal(auth.verifyTotp(secret, '287082', 59000), 1);
  const now = Date.now(), step = Math.floor(now / 30000);
  assert.equal(auth.verifyTotp(secret, auth.totpAt(secret, step - 1), now), step - 1);
  assert.equal(auth.verifyTotp(secret, auth.totpAt(secret, step - 3), now), -1);
  assert.equal(auth.verifyTotp(secret, 'abc123', now), -1);
});
test('login limit: 5 wrong tries lock for 15 minutes', () => {
  const keys = ['e:x@y', 'ip:1.2.3.4']; auth.clearFails(keys);
  for (let i = 0; i < 4; i++) auth.recordFail(keys);
  assert.equal(auth.lockedFor(keys), 0); assert.equal(auth.triesLeft(keys), 1);
  auth.recordFail(keys);
  assert.ok(auth.lockedFor(keys) > 14 * 60 * 1000);
  assert.equal(auth.lockedFor(keys, Date.now() + 16 * 60 * 1000), 0);
  auth.clearFails(keys);
});
test('CSV export neutralises spreadsheet formulas', () => {
  const csv = core.toCsv([{ a: '=HYPERLINK("x")', b: 'plain, text' }], ['a', 'b']);
  assert.match(csv, /"'=HYPERLINK\(""x""\)"/); assert.match(csv, /"plain, text"/);
});

function app(sessionSeed) {
  const a = express(); a.use(express.json());
  const store = { ...sessionSeed };
  a.use((rq, rs, next) => { rq.session = store; next(); });
  a.use('/admin/api', req('admin/adminRoutes'));
  return new Promise(r => { const s = a.listen(0, () => r({ s, store, url: `http://127.0.0.1:${s.address().port}/admin/api` })); });
}
const post = (url, body) => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'User-Agent': 'Mozilla/5.0 (Macintosh) Chrome/1' }, body: JSON.stringify(body || {}) });

test('sign-in: password then 2-step code; a code works once; lockout after 5 misses', async () => {
  const secret = auth.newTotpSecret();
  const admin = { admin_id: 'a1', email: 'boss@x.com', password: auth.hashPassword('Kathmandu2026'), role: 'superadmin', is_active: 1, totp_enabled: 1, totp_secret: seal(secret), totp_last_step: 0, recovery_codes: JSON.stringify([auth.sha256('aaaaa-bbbbb')]) };
  const logs = [];
  Object.assign(adb, { getAdminFull: async (e) => e === admin.email ? admin : null, getAdminById: async () => admin,
    setTotpStep: async (id, st) => { admin.totp_last_step = st; }, setRecoveryCodes: async (id, l) => { admin.recovery_codes = JSON.stringify(l); },
    seenDevice: async () => true, setAdminPassword: async () => {} });
  Object.assign(db, { logActivity: async (...a) => logs.push(a[2]), updateAdminLastLogin: async () => {} });
  auth._fails.clear();
  const { s, store, url } = await app({});
  try {
    let r = await (await post(`${url}/login`, { email: 'boss@x.com', password: 'Kathmandu2026' })).json();
    assert.equal(r.needs2fa, true); assert.ok(!store.admin);
    const code = auth.totpAt(secret, Math.floor(Date.now() / 30000));
    r = await (await post(`${url}/login/2fa`, { code })).json();
    assert.equal(r.success, true); assert.equal(store.admin.email, 'boss@x.com'); assert.ok(logs.includes('NEW_DEVICE_LOGIN'));
    // same code again is refused
    store.admin = null; await post(`${url}/login`, { email: 'boss@x.com', password: 'Kathmandu2026' });
    assert.equal((await post(`${url}/login/2fa`, { code })).status, 401);
    // recovery code works once
    assert.equal((await (await post(`${url}/login/2fa`, { recovery: 'AAAAA-BBBBB' })).json()).success, true);
    assert.equal(JSON.parse(admin.recovery_codes).length, 0);
    // lockout
    auth._fails.clear(); store.admin = null;
    let last;
    for (let i = 0; i < 5; i++) last = await post(`${url}/login`, { email: 'boss@x.com', password: 'wrong-password-1' });
    assert.equal(last.status, 429);
    assert.equal((await post(`${url}/login`, { email: 'boss@x.com', password: 'Kathmandu2026' })).status, 429);
  } finally { s.close(); auth._fails.clear(); }
});

test('idle for 30 minutes signs you out; read-only mode blocks changes', async () => {
  const a = core.sessionFor({ admin_id: 'a1', email: 'boss@x.com', role: 'superadmin' });
  Object.assign(adb, { listBlocklist: async () => [], addBlock: async () => {} });
  Object.assign(db, { logActivity: async () => {} });
  const { s, store, url } = await app({ admin: { ...a, lastSeen: Date.now() - 31 * 60 * 1000 } });
  try {
    const r = await fetch(`${url}/blocklist`); assert.equal(r.status, 401); assert.equal((await r.json()).expired, true);
    store.admin = { ...a, lastSeen: Date.now() };
    await post(`${url}/me/readonly`, { on: true });
    assert.equal((await post(`${url}/blocklist`, { domain: 'bad.com' })).status, 423);
    assert.equal((await fetch(`${url}/blocklist`)).status, 200);
    await post(`${url}/me/readonly`, { on: false });
    assert.equal((await post(`${url}/blocklist`, { domain: 'https://www.Bad-Site.com/login' })).status, 200);
    assert.equal((await post(`${url}/blocklist`, { domain: 'gmail.com' })).status, 400);
  } finally { s.close(); }
});

test('approvals: a moderator asks, a superadmin approves; nobody approves their own request', async () => {
  const actions = {}; let deleted = null;
  Object.assign(adb, {
    requestAction: async (action, payload, summary, by) => { const id = 'act1'; actions[id] = { action_id: id, action, payload: JSON.stringify(payload), summary, requested_by: by, status: 'pending' }; return id; },
    getAction: async (id) => actions[id], decideAction: async (id, st) => { actions[id].status = st; }, markDone: async () => {} });
  Object.assign(db, { logActivity: async () => {}, deleteAdmin: async (id) => { deleted = id; },
    query: async (sql) => /COUNT/.test(sql) ? { rows: [{ n: 0 }] } : { rows: [{ email: 'old@x.com', role: 'viewer' }] } });
  const mod = core.sessionFor({ admin_id: 'm1', email: 'mod@x.com', role: 'moderator' });
  const { s, store, url } = await app({ admin: mod });
  try {
    let r = await (await post(`${url}/actions`, { action: 'delete_admin', payload: { adminId: 'v9' } })).json();
    assert.equal(r.pending, true); assert.equal(deleted, null);
    assert.equal((await post(`${url}/actions/act1/approve`)).status, 403);           // moderators can't approve
    store.admin = core.sessionFor({ admin_id: 's1', email: 'boss@x.com', role: 'superadmin' });
    assert.equal((await (await post(`${url}/actions/act1/approve`)).json()).success, true);
    assert.equal(deleted, 'v9');
    // the only superadmin acts directly
    deleted = null;
    r = await (await post(`${url}/actions`, { action: 'delete_admin', payload: { adminId: 'v8' } })).json();
    assert.equal(r.done, true); assert.equal(deleted, 'v8');
  } finally { s.close(); }
});

test('global block list makes a domain dangerous for everyone', async () => {
  const { analyseEmail } = req('services/threatService');
  const r = await analyseEmail({ id: '1', from: 'Shop <deals@nice-shop.com>', subject: 'hi', body: 'hello', links: [], attachments: [] }, { domainAge: false, blockedDomains: new Set(['nice-shop.com']) });
  assert.equal(r.level, 'dangerous'); assert.match(r.reasons[0], /global block list/);
});

test('sender origin: first public IP in Received headers, country offline', () => {
  const geo = req('services/geo');
  const ip = geo.originIp({ received: ['from mail.example (unknown [102.89.34.10]) by mx.google.com', 'from [10.0.0.5] by mail.example'] });
  assert.equal(ip, '102.89.34.10'); assert.equal(geo.countryOf(ip).code, 'NG');
  assert.equal(geo.originIp({ received: ['from x ([192.168.1.4]) by y'] }), null);
  assert.equal(geo.originIp({ xOriginatingIp: '[27.34.16.1]' }), '27.34.16.1');
});
