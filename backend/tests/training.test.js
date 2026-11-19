// The model that keeps learning from real scams
const { test } = require('node:test');
const assert = require('node:assert');
const { req } = require('./_setup');
const t = req('services/modelTrainer');
const ml = req('services/mlService');

test('personal details are removed before an example is saved', () => {
  const r = t.redact('Pay to 0123 4567 8901 or TQrY8tryqsYVCYS3MFbtffiPp2ccyn4STm, write boss@scam.biz, open https://www.paypa1-verify.co/x?id=9, call +977 9812345678');
  for (const bad of ['0123', 'TQrY8', 'boss@', 'id=9', '9812345678']) assert.ok(!r.includes(bad), bad);
  assert.match(r, /link paypa1-verify\.co/); assert.match(r, /cryptowallet/); assert.match(r, /emailaddress/);
});

test("the recipient's own name is removed too", () => {
  const r = t.redact('Dear Prince Magar, your esewa account prince.magar is blocked. Prince, send your mpin', ['Prince', 'Magar', 'prince.magar']);
  assert.ok(!/prince|magar/i.test(r), r); assert.match(r, /recipientname/);
});

test('deleting an account keeps training examples, unlinked from the person', async () => {
  const db = req('database/db'); const sqls = [];
  db.pool.connect = async () => ({ query: async (q, p) => { sqls.push([q, p]); return { rows: [] }; }, release() {} });
  await db.deleteUserData('u1');
  assert.ok(sqls.some(([q]) => /UPDATE training_samples SET user_id=NULL WHERE user_id=\$1/.test(q)));
  assert.ok(!sqls.some(([q]) => /DELETE FROM training_samples/.test(q)));
});

test('the most trusted label wins, labels stay balanced, the test split never changes', () => {
  const rows = [
    { label: 'phishing', source: 'auto_clear', source_ref: 'e1', text: 'x' },
    { label: 'safe', source: 'admin_false_alarm', source_ref: 'e1', text: 'x' },        // admin overrules the automatic label
    ...Array.from({ length: 200 }, (_, i) => ({ label: 'phishing', source: 'honeypot', source_ref: 'h' + i, text: 'send fee now' })),
    ...Array.from({ length: 20 }, (_, i) => ({ label: 'safe', source: 'newsletter', source_ref: 'n' + i, text: 'weekly digest' })),
  ];
  const p = t.prepare(rows);
  const e1 = [...p.train, ...p.test].filter(r => r.source_ref === 'e1');
  assert.equal(e1.length, 1); assert.equal(e1[0].label, 'safe');
  assert.equal(p.counts.safe, 21); assert.equal(p.counts.phishing, 63);                // at most 3 scams per safe example
  assert.deepEqual(t.prepare(rows).test.map(r => r.source_ref), p.test.map(r => r.source_ref));
  assert.ok(p.test.length > 0 && p.test.every(r => t.isTest(r.source_ref)));
});

test('learning from real scams catches scams the built-in examples miss', () => {
  const scams = ['your esewa wallet kyc pending submit citizenship photo and mpin to avoid block', 'nabil bank notice update khalti pin to receive refund today',
    'dear winner your ncell lucky draw prize send processing fee to claim', 'agent here send usdt deposit fee then your parcel releases from customs',
    'congratulations scholarship approved pay registration fee via fonepay now', 'job offer dubai visa processing charge deposit to agent account'];
  const safes = ['school timetable for class nine updated please check notice board', 'parents meeting saturday at 10 in the hall bring report card',
    'weekly newsletter from neon new features in the console', 'your daraz order has shipped track it in the app', 'staff lunch on friday please confirm',
    'exam results published on the college website'];
  const mk = (arr, label, k) => Array.from({ length: k }, (_, i) => ({ label, source: 'x', source_ref: `${label}${i}`, text: arr[i % arr.length] + ' ' + i }));
  const rows = [...mk(scams, 'phishing', 60), ...mk(safes, 'safe', 60)];
  const { train, test } = t.prepare(rows);
  const before = t.evaluate(t.build([]), test), after = t.evaluate(t.build(train), test);
  assert.ok(after.f1 > before.f1, `${after.f1} > ${before.f1}`);
  assert.ok(after.accuracy >= 0.9, String(after.accuracy));
  assert.ok(t.better(after, before)); assert.ok(!t.better(before, after));
});

test('a retrained model can be saved, loaded and used by the scanner', () => {
  const natural = require('natural');
  const c = t.build([{ label: 'phishing', text: 'esewa kyc mpin block submit' }, { label: 'safe', text: 'class timetable notice board' }]);
  const loaded = natural.BayesClassifier.restore(JSON.parse(JSON.stringify(c)));
  ml.setClassifier(loaded, 'auto-test');
  assert.equal(ml.getModelVersion(), 'auto-test');
  assert.equal(ml.classifyText('please submit your esewa kyc and mpin or we block the wallet').label, 'phishing');
});

test('the starter dataset loads and beats the 40 built-in examples on unseen messages', () => {
  const ds = t.readDataset();
  assert.ok(ds.filter(d => d.label === 'phishing').length >= 100 && ds.filter(d => d.label === 'safe').length >= 90, 'dataset size');
  assert.ok(ds.some(d => d.region === 'nepal' && /esewa|khalti|ncell/i.test(d.text)), 'has Nepal scams');
  const rows = ds.map((d, i) => ({ label: d.label, source: 'dataset', source_ref: 'ds' + i, text: d.text }));
  const { train, test: unseen } = t.prepare(rows);
  const before = t.evaluate(t.build([]), unseen), after = t.evaluate(t.build(train), unseen);
  assert.ok(after.f1 > before.f1, `${after.f1} > ${before.f1}`);
  assert.ok(after.accuracy >= 0.88, String(after.accuracy));
});
