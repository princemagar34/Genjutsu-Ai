const { test } = require('node:test');
const assert = require('node:assert');
const { req, NO_NET, PASS_AUTH } = require('./_setup');
const { analyseEmail } = req('services/threatService');
const rules = req('services/rules'); const alerts = req('services/alerts'); const nami = req('services/nami'); const siem = req('services/siem');
const { rateLimit } = req('middleware/rateLimit'); const { buildDigest } = req('services/digest'); const db = req('database/db');
const R = (field, value, action) => ({ rule_id: 'r', field, value, action });
const base = { links: [], attachments: [], authResults: PASS_AUTH('mail.college.edu.np') };

test('rules: trust domain, quarantine attachment, flag subject, never trust a spoof', async () => {
  assert.equal((await analyseEmail({ ...base, from: 'T <t@mail.college.edu.np>', subject: 'act now urgent', body: 'act now' }, { ...NO_NET, rules: [R('domain', 'college.edu.np', 'trust')] })).level, 'safe');
  const q = await analyseEmail({ ...base, from: 'x <x@shop.com>', subject: 'Invoice', body: 'hi', attachments: [{ filename: 'a.zip' }] }, { ...NO_NET, rules: [R('attachment', 'zip', 'quarantine')] });
  assert.equal(q.level, 'dangerous'); assert.equal(q.quarantineByRule, true);
  assert.equal((await analyseEmail({ ...base, from: 'x <x@shop.com>', subject: 'lottery win', body: 'hi' }, { ...NO_NET, rules: [R('subject', 'lottery', 'flag')] })).level, 'suspicious');
  assert.notEqual((await analyseEmail({ ...base, from: 'PayPal <h@pay-help.com>', body: 'verify your account', authResults: '' }, { ...NO_NET, rules: [R('domain', 'pay-help.com', 'trust')] })).level, 'safe');
  assert.ok(rules.validateRule({ field: 'domain', value: 'nope', action: 'trust' }));
});
test('Discord: only real webhook URLs, stored encrypted', () => {
  assert.ok(alerts.isDiscordWebhook('https://discord.com/api/webhooks/1/ab-C_9'));
  assert.ok(!alerts.isDiscordWebhook('https://evil.com/api/webhooks/1/a'));
  assert.ok(!alerts.sealWebhook('https://discord.com/api/webhooks/1/abc').includes('discord'));
});
test('rate limit', async () => {
  const lim = rateLimit({ name: 'test', windowMs: 60000, max: 2 }); let blocked = 0;
  for (let i = 0; i < 4; i++) await new Promise(r => lim({ session: { user: { id: 'u' } } }, { set() {}, status() { blocked++; return { json: r }; } }, r));
  assert.equal(blocked, 2);
});
test('weekly digest text', () => {
  const d = buildDigest({ name: 'Prince Magar' }, { total: 50, dangerous: 1, suspicious: 3, quarantined: 1, honeypotSessions: 1, honeypotMinutes: 47, top: [{ subject: 'S', sender_email: 'x@y.z', confidence_score: 0.9 }] });
  assert.match(d.subject, /1 dangerous email/); assert.ok(d.text.startsWith('Hi Prince,'));
});
test('delete account removes every table, users last', async () => {
  const sqls = []; db.pool.connect = async () => ({ query: async (s) => { sqls.push(s); return { rows: [] }; }, release() {} });
  await db.deleteUserData('u1');
  for (const t of ['honeypot_messages', 'emails', 'user_api_keys', 'user_rules', 'user_sessions', 'users']) assert.ok(sqls.some(s => new RegExp(`FROM ${t}\\b`).test(s)), t);
  assert.match(sqls.at(-1), /FROM users WHERE/);
});
test('Nami: personas, safety stop, no real-looking data, intel extraction', () => {
  assert.equal(Object.keys(nami.PERSONAS).length, 4);
  assert.ok(nami.safetyCheck('I will hurt your family')); assert.ok(!nami.safetyCheck('Pay the 50 dollar fee'));
  assert.equal(nami.sanitiseReply('my account is 0123 4567 8901'), null);
  const i = nami.extractIntel('USDT TQrY8tryqsYVCYS3MFbtffiPp2ccyn4STm, Account No: 0123456789012, WhatsApp +977 9812345678, fee 2500');
  assert.equal(i.crypto.length, 1); assert.deepEqual(i.bankAccounts, ['0123456789012']); assert.ok(i.phones.includes('+9779812345678'));
});
test('SIEM: CEF and syslog lines', () => {
  const ev = siem.toEvents({ email: 'me@x' }, [{ gmail_message_id: 'm', sender_email: 'a@b.c', subject: 'x|y', confidence_score: 0.9, scanned_at: new Date(), threat_type: 'dangerous', details: '[]', mitre: '[{"id":"T1656","name":"Impersonation"}]', iocs: '{}' }], []);
  assert.match(siem.toCef(ev[0]), /^CEF:0\|Genjutsu\|Email Security\|3\.1\|EMAIL-DANGEROUS\|/);
  assert.match(siem.render(ev, 'syslog').body, /^<130>1 /);
});
