// Shared threat feed + sender history
const { test } = require('node:test');
const assert = require('node:assert');
const { req, NO_NET, PASS_AUTH } = require('./_setup');
const feed = req('services/sharedFeed');
const { analyseEmail } = req('services/threatService');
const HARDR = JSON.stringify(['Look-alike sender domain: paypa1-help.co imitates paypal']);
const row = (user, from, extra = {}) => ({ user_id: user, sender_email: from, at: new Date(), details: HARDR, iocs: '{}', ...extra });

test('an attacker becomes active only after hitting 2 different users', () => {
  const one = feed.indicatorsFrom([row('u1', 'PayPal <a@paypa1-help.co>'), row('u1', 'PayPal <b@paypa1-help.co>')]);
  assert.equal(one.find(i => i.value === 'paypa1-help.co').status, 'watch');
  const two = feed.indicatorsFrom([row('u1', 'PayPal <a@paypa1-help.co>'), row('u2', 'PayPal <c@paypa1-help.co>')]);
  const i = two.find(x => x.value === 'paypa1-help.co'); assert.equal(i.status, 'active'); assert.equal(i.users, 2);
  // an admin-confirmed threat counts with one user
  assert.equal(feed.indicatorsFrom([row('u1', 'X <a@bad-one.co>', { review: 'confirmed' })])[0].status, 'active');
});
test('gmail senders are shared by address; big real services and soft signals are never shared', () => {
  const inds = feed.indicatorsFrom([
    row('u1', 'Boss <ceo.urgent22@gmail.com>'), row('u2', 'Boss <ceo.urgent22@gmail.com>'),
    row('u1', 'x <a@evil.biz>', { iocs: JSON.stringify({ urls: ['https://docs.google.com/x', 'https://bit.ly/abc', 'http://steal-login.xyz/p'] }) }),
    row('u3', 'Shop <deals@shop.example>', { details: JSON.stringify(['Urgency word: "act now"']) }),
  ]);
  assert.ok(inds.find(i => i.kind === 'sender' && i.value === 'ceo.urgent22@gmail.com' && i.status === 'active'));
  assert.ok(!inds.find(i => i.value === 'gmail.com' || i.value === 'google.com' || i.value === 'bit.ly'));
  assert.ok(inds.find(i => i.value === 'steal-login.xyz'));
  assert.ok(!inds.find(i => i.value === 'shop.example'), 'only hard signs feed the shared list');
});
test('a scan matching the shared feed is dangerous and says why', async () => {
  const ctx = { ...NO_NET, shared: { domains: new Map([['paypa1-help.co', 3]]), senders: new Map() } };
  const r = await analyseEmail({ id: 'n1', from: 'Support <hi@paypa1-help.co>', subject: 'hello', body: 'hello', links: [], attachments: [] }, ctx);
  assert.equal(r.level, 'dangerous'); assert.match(r.reasons[0], /Seen in attacks on 3 Genjutsu users/); assert.equal(r.subType, 'phishing');
});
test('first-time sender adds weight only when there are other warning signs', async () => {
  const shady = { id: 'm9', from: 'Prize <win@lucky-draw.biz>', subject: 'You won', body: 'verify your account to claim your prize', links: [], attachments: [] };
  const first = await analyseEmail(shady, { ...NO_NET, seen: {} });
  assert.equal(first.senderHistory.firstTime, true); assert.ok(first.reasons.some(r => r.startsWith('First email from this sender')));
  const known = await analyseEmail(shady, { ...NO_NET, seen: { 'win@lucky-draw.biz': { n: 4, ids: ['a', 'b', 'c', 'd'], first: new Date() } } });
  assert.equal(known.senderHistory.earlier, 4); assert.ok(!known.reasons.some(r => r.startsWith('First email')));
  assert.ok(first.score > known.score);
  const friend = await analyseEmail({ id: 'f1', from: 'Sita <sita@gmail.com>', subject: 'lunch', body: 'lunch friday?', links: [], attachments: [], authResults: PASS_AUTH('gmail.com') }, { ...NO_NET, seen: {} });
  assert.equal(friend.level, 'safe'); assert.ok(!friend.reasons.some(r => r.startsWith('First email')));
  // the email itself already saved does not count as "earlier"
  const again = await analyseEmail(shady, { ...NO_NET, seen: { 'win@lucky-draw.biz': { n: 1, ids: ['m9'], first: new Date() } } });
  assert.equal(again.senderHistory.firstTime, true);
});
