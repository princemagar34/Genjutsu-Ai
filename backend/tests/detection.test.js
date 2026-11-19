const { test } = require('node:test');
const assert = require('node:assert');
const { req, NO_NET, PASS_AUTH, FAIL_AUTH } = require('./_setup');
const { analyseEmail } = req('services/threatService');
const det = req('services/detection');
const scan = (email, ctx = NO_NET) => analyseEmail({ id: 'x', links: [], attachments: [], ...email }, ctx);
const neon = { from: 'Neon <product@email.neon.tech>', subject: 'Welcome to Neon', body: 'Alert: the free plan includes 0.5 GB.', links: Array.from({ length: 7 }, (_, i) => `https://neon.com/${i}`) };

test('verified newsletter is safe and labelled', async () => {
  const r = await scan({ ...neon, authResults: PASS_AUTH('email.neon.tech'), listUnsubscribe: '<x>' });
  assert.equal(r.level, 'safe'); assert.equal(r.category, 'newsletter');
});
test('same email without verification is still checked', async () => {
  assert.notEqual((await scan({ ...neon, authResults: FAIL_AUTH })).level, 'safe');
});
test('display-name spoofing', async () => {
  const r = await scan({ from: 'PayPal Security <alerts@secure-mail-center.com>', subject: 'Limited', body: 'Please verify your account', authResults: PASS_AUTH('secure-mail-center.com') });
  assert.notEqual(r.level, 'safe');
  assert.ok(r.mitre.some(m => m.id === 'T1656') && r.mitre.some(m => m.id === 'T1598'));
});
test('look-alike link + IOC', async () => {
  const r = await scan({ from: 'Service <service@notice-center.co>', subject: 'Action needed', body: 'Confirm here http://paypa1-verify.co/login', links: ['http://paypa1-verify.co/login'] });
  assert.ok(r.reasons.some(x => x.startsWith('Look-alike link domain')));
  assert.equal(r.level, 'dangerous'); assert.ok(r.iocs.urls.includes('http://paypa1-verify.co/login'));
});
test('business email compromise with Reply-To to Gmail', async () => {
  const r = await scan({ from: 'Accounts <billing@acme-supplies.com>', replyTo: 'acme.billing@gmail.com', subject: 'Bank details', body: 'Please note our change of bank details.', authResults: PASS_AUTH('acme-supplies.com') });
  assert.equal(r.level, 'dangerous'); assert.ok(r.iocs.emails.includes('acme.billing@gmail.com'));
});
test('hidden link is caught, newsletter click-tracking is not', async () => {
  const bad = await scan({ from: 'Nabil <a@nabil-notify.info>', body: 'x', html: '<a href="http://login-secure.xyz/n">www.nabilbank.com</a>', links: ['http://login-secure.xyz/n'] });
  assert.ok(bad.reasons.some(x => x.startsWith('Hidden link')));
  const ok = await scan({ from: 'Neon <a@email.neon.tech>', body: 'x', html: '<a href="https://click.neon.tech/a">neon.com/docs</a>', links: ['https://click.neon.tech/a'], authResults: PASS_AUTH('email.neon.tech'), listUnsubscribe: '<x>' });
  assert.ok(!ok.reasons.some(x => x.startsWith('Hidden link')));
});
test('forged google.com is not let through by the trusted-domain cap', async () => {
  const r = await scan({ from: 'Google <no-reply@accounts.google.com>', body: 'Verify your account http://198.51.100.7/x', links: ['http://198.51.100.7/x'], authResults: FAIL_AUTH });
  assert.equal(r.level, 'dangerous');
});
test('genuine Google alert stays safe', async () => {
  assert.equal((await scan({ from: 'Google <no-reply@accounts.google.com>', subject: 'Security alert', body: 'New sign-in on Mac.', authResults: PASS_AUTH('accounts.google.com') })).level, 'safe');
});
test('trusted sender helps, but never hides a forged one', async () => {
  const ctx = { ...NO_NET, safeSenders: new Set(['news@dazn.com']), history: {} };
  assert.equal((await scan({ from: 'DAZN <news@dazn.com>', subject: 'act now', body: 'urgent limited time offer act now', links: Array(8).fill('https://dazn.com') }, ctx)).level, 'safe');
  assert.notEqual((await scan({ from: 'DAZN <news@dazn.com>', replyTo: 'r@gmail.com', body: 'change of bank details', authResults: FAIL_AUTH }, ctx)).level, 'safe');
});
test('new domain via RDAP; offline lookups never penalise', async () => {
  const fresh = async () => ({ ok: true, json: async () => ({ events: [{ eventAction: 'registration', eventDate: new Date(Date.now() - 5 * 864e5).toISOString() }] }) });
  const r = await scan({ from: 'S <h@fresh-deals-portal.com>', body: 'x', links: ['https://fresh-deals-portal.com/t'] }, { fetch: fresh });
  assert.ok(r.reasons.some(x => x.startsWith('New domain: fresh-deals-portal.com')));
  det._ageCache.clear();
  assert.equal((await scan({ from: 'S <h@some-shop.com>', body: 'hi' }, { fetch: async () => { throw new Error('offline'); } })).level, 'safe');
});
test('look-alike domain cases', () => {
  const la = (d) => det.lookalikeBrand(d)?.brand || null;
  for (const [d, want] of [['paypa1.com', 'paypal'], ['g00gle.com', 'google'], ['arnazon.com', 'amazon'], ['linkedln.com', 'linkedin'], ['paypal-secure-login.com', 'paypal'], ['docusing.net', 'docusign'],
    ['finance.com', null], ['google-analytics.com', null], ['neon.tech', null], ['nabilbank.com', null], ['esewa.com.np', null]]) assert.equal(la(d), want, d);
});
test('HTML-only email becomes text', () => {
  assert.equal(det.htmlToText('<style>x{}</style><p>Hello&nbsp;<b>Prince</b></p><div>Line&amp;2</div>'), 'Hello Prince\nLine&2');
});

test('each threat lands on the right Threat Analysis card', async () => {
  const cases = [
    [{ from: 'PayPal <alerts@paypa1-verify.co>', subject: 'Verify', body: 'Verify your account now http://paypa1-verify.co/login', links: ['http://paypa1-verify.co/login'] }, 'phishing'],
    [{ from: 'Nabil <a@nabil-notify.info>', body: 'x', html: '<a href="http://login-secure.xyz/n">www.nabilbank.com</a>', links: ['http://login-secure.xyz/n'] }, 'phishing'],
    [{ from: 'HR <hr@payroll-docs.biz>', subject: 'Salary', body: 'open the file', attachments: [{ filename: 'salary.pdf.exe' }] }, 'malware_link'],
    [{ from: 'Accounts <billing@acme-supplies.com>', replyTo: 'acme.billing@gmail.com', body: 'Please note our change of bank details', authResults: PASS_AUTH('acme-supplies.com') }, 'spoofed_sender'],
    [{ from: 'PayPal Security <alerts@secure-mail-center.com>', body: 'Please verify your account', authResults: PASS_AUTH('secure-mail-center.com') }, 'spoofed_sender'],
  ];
  for (const [email, want] of cases) assert.equal((await scan(email)).subType, want, email.from);
  assert.equal((await scan({ from: 'Neon <a@email.neon.tech>', body: 'hi', authResults: PASS_AUTH('email.neon.tech'), listUnsubscribe: '<x>' })).subType, null);
});

test('re-sorting saved threats gives the same type as the scanner', async () => {
  const { subtypeFromReasons } = req('services/threatRecords');
  const emails = [
    { from: 'PayPal <alerts@paypa1-verify.co>', subject: 'Verify', body: 'Verify your account now http://paypa1-verify.co/login', links: ['http://paypa1-verify.co/login'] },
    { from: 'Nabil <a@nabil-notify.info>', body: 'x', html: '<a href="http://login-secure.xyz/n">www.nabilbank.com</a>', links: ['http://login-secure.xyz/n'] },
    { from: 'HR <hr@payroll-docs.biz>', subject: 'Salary', body: 'open the file', attachments: [{ filename: 'salary.pdf.exe' }] },
    { from: 'Accounts <billing@acme-supplies.com>', replyTo: 'acme.billing@gmail.com', body: 'Please note our change of bank details', authResults: PASS_AUTH('acme-supplies.com') },
    { from: 'PayPal Security <alerts@secure-mail-center.com>', body: 'Please verify your account', authResults: PASS_AUTH('secure-mail-center.com') },
    { from: 'College <registrar@college.edu.np>', subject: 'act now urgent', body: 'urgent verify your account act now limited time', links: ['http://203.0.113.9/x'] },
  ];
  for (const e of emails) { const r = await scan(e); assert.equal(subtypeFromReasons(r.reasons), r.subType, e.from); }
});
