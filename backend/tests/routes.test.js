// Route-level tests with a fake mailbox and database
const { test } = require('node:test');
const assert = require('node:assert');
const { req } = require('./_setup');
const express = require('express');
const db = req('database/db'); const mail = req('services/mail');

function serve(router, mount, user) {
  const app = express(); app.use(express.json());
  app.use((rq, rs, next) => { rq.session = { user }; next(); });
  app.use(mount, router);
  return new Promise(r => { const s = app.listen(0, () => r({ s, url: `http://127.0.0.1:${s.address().port}${mount}` })); });
}

test('quarantine: only dangerous, never honeypot threads or emails you marked safe; off when disabled', async () => {
  const moved = [], blocked = []; let settings = { auto_block: 1 };
  mail.fetchEmails = async () => [
    { id: 'phish', from: 'PayPal <h@paypa1-help.com>', subject: 'v', body: 'verify your account', links: ['http://paypa1-help.com/x'], attachments: [] },
    { id: 'loop', from: 'S <s@scam.biz>', threadId: 'T1', subject: 'r', body: 'verify your account urgent act now', links: ['http://203.0.113.9/x'], attachments: [] },
    { id: 'okd', from: 'PayPal <h@paypa1-help.com>', subject: 'v2', body: 'verify your account', links: ['http://paypa1-help.com/y'], attachments: [] }];
  mail.moveToSpam = async (u, id) => moved.push(id);
  Object.assign(db, { getSystemSetting: async () => '50', getScanContext: async () => ({ safeSenders: new Set(), history: {}, rules: [], domainAge: false }), saveEmailScan: async () => {},
    getHoneypotSessions: async () => [{ status: 'active', sender_email: 's@scam.biz', thread_id: 'T1' }], getThreatOverride: async (id) => id.endsWith('-okd') ? { new_level: 'safe' } : null,
    getSettings: async () => settings, getBlockedEmails: async () => [], blockEmail: async (...a) => blocked.push(a), logUserActivity: async () => {} });
  const { s, url } = await serve(require('../routes/emails'), '/api', { id: 'u1', provider: 'google' });
  try {
    const j = await (await fetch(`${url}/emails`)).json();
    assert.deepEqual(moved, ['phish']); assert.equal(blocked[0][5], 'auto'); assert.equal(j.quarantined.length, 1);
    moved.length = 0; settings = { auto_block: 0 }; await fetch(`${url}/emails`); assert.equal(moved.length, 0);
  } finally { s.close(); }
});

test('Nami: a threat ends the conversation without replying', async () => {
  const sent = [], ended = [];
  Object.assign(db, { getHoneypotSessions: async () => [{ session_id: 's1', status: 'active', sender_email: 'x@y.biz', subject: 'Re', replies_sent: 1, started_at: new Date(Date.now() - 36e5).toISOString(), last_reply_at: new Date(Date.now() - 6e5).toISOString(), persona: 'student' }],
    saveHoneypotMessage: async () => {}, updateHoneypotSession: async () => {}, endHoneypotSession: async (id, why) => ended.push(why), logUserActivity: async () => {}, getHoneypotMessages: async () => [] });
  mail.findLatestFrom = async () => ({ id: 'm', text: 'Pay or I will hurt your family', messageId: '<m>' });
  mail.sendReply = async (...a) => sent.push(a);
  const { s, url } = await serve(require('../routes/honeypot'), '/api', { id: 'u1', name: 'P', email: 'me@x', provider: 'google' });
  try {
    const j = await (await fetch(`${url}/honeypot/poll`, { method: 'POST' })).json();
    assert.equal(sent.length, 0); assert.equal(ended[0], 'The sender made a violent threat'); assert.ok(j.results[0].stopped);
  } finally { s.close(); }
});

test('API: key required, /check works', async () => {
  Object.assign(db, { findUserByApiKey: async (k) => k === 'gj_good_aaaaaaaaaaaaaaaaaaaaaa' ? { id: 'u1', email: 'me@x', keyId: 'k' } : null,
    getScanContext: async () => ({ safeSenders: new Set(), history: {}, rules: [], domainAge: false }) });
  const { s, url } = await serve(require('../routes/publicApi'), '/api/v1', null);
  try {
    assert.equal((await fetch(`${url}/check`, { method: 'POST' })).status, 401);
    const r = await (await fetch(`${url}/check`, { method: 'POST', headers: { Authorization: 'Bearer gj_good_aaaaaaaaaaaaaaaaaaaaaa', 'Content-Type': 'application/json' }, body: JSON.stringify({ from: 'PayPal <a@secure-center.com>', body: 'verify your account http://paypa1-verify.co/x' }) })).json();
    assert.equal(r.result.level, 'dangerous');
  } finally { s.close(); }
});

test('demo mailbox: samples classify as intended', async () => {
  const demo = req('services/mail/demoProvider'); const { analyseEmail } = req('services/threatService');
  const want = { 'demo-1': 'dangerous', 'demo-2': 'dangerous', 'demo-3': 'dangerous', 'demo-4': 'dangerous', 'demo-5': 'safe', 'demo-6': 'safe', 'demo-7': 'safe', 'demo-8': 'safe', 'demo-9': 'dangerous', 'demo-10': 'dangerous' };
  const user = { id: 'demo-t', provider: 'demo' };
  const emails = await demo.fetchEmails(user);
  Object.assign(db, { query: async () => ({ rows: [] }) });   // no attachment cache in this test
  await req('services/attachmentScanner').prepare(user, emails, { getAttachment: (u, e, a) => demo.getAttachment(u, e, a) });
  const types = {};
  for (const e of emails) { const r = await analyseEmail(e, { domainAge: false }); assert.equal(r.level, want[e.id], e.id); types[e.id] = r.subType; }
  assert.equal(types['demo-9'], 'phishing'); assert.equal(types['demo-10'], 'malware_link'); assert.equal(types['demo-4'], 'malware_link');
});
