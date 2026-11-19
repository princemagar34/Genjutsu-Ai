const { test } = require('node:test');
const assert = require('node:assert');
const { req } = require('./_setup');
const { parseEmail } = req('services/gmailService');
const { sealUserTokens, withTokens, sealColumn } = req('services/mail/tokens');
const mail = req('services/mail');
const b64 = s => Buffer.from(s).toString('base64').replace(/\+/g, '-').replace(/\//g, '_');
const H = o => Object.entries(o).map(([name, value]) => ({ name, value }));

test('Gmail: nested multipart, HTML links, List-Unsubscribe, attachments', () => {
  const e = parseEmail({ id: '1', threadId: 't', snippet: '', labelIds: [], payload: { mimeType: 'multipart/mixed', headers: H({ From: 'a@b.c', 'List-Unsubscribe': '<x>' }), parts: [
    { mimeType: 'multipart/alternative', parts: [{ mimeType: 'text/plain', body: { data: b64('Plain https://a.com/1') } }, { mimeType: 'text/html', body: { data: b64('<a href="https://a.com/2">x</a>') } }] },
    { mimeType: 'application/pdf', filename: 'f.pdf', body: { attachmentId: 'z' } }] } });
  assert.ok(e.body.startsWith('Plain')); assert.deepEqual(e.links.sort(), ['https://a.com/1', 'https://a.com/2']);
  assert.equal(e.listUnsubscribe, '<x>'); assert.equal(e.attachments.length, 1);
});
test('Gmail: HTML-only and single-part emails', () => {
  assert.equal(parseEmail({ id: '2', payload: { mimeType: 'text/html', headers: [], body: { data: b64('<div>Only <b>HTML</b></div>') } } }).body, 'Only HTML');
  assert.equal(parseEmail({ id: '3', payload: { mimeType: 'text/plain', headers: [], body: { data: b64('Single') } } }).body, 'Single');
});
test('tokens: sealed in the session, opened only for a call', async () => {
  const u = sealUserTokens({ id: 'g', provider: 'google', accessToken: 'ya29.SECRET', refreshToken: '1//R' });
  assert.ok(!JSON.stringify(u).includes('SECRET'));
  let seen; mail.providers.google.fetchEmails = async (ctx) => { seen = ctx.accessToken; return []; };
  await mail.fetchEmails(u); assert.equal(seen, 'ya29.SECRET'); assert.ok(!('accessToken' in u));
});
test('tokens: Outlook refresh saved encrypted, even if the call fails', async () => {
  mail.providers.microsoft.createSpamFilter = async (ctx) => { ctx.accessToken = 'NEW'; throw new Error('x'); };
  const u = sealUserTokens({ id: 'm', provider: 'microsoft', accessToken: 'OLD', refreshToken: 'R' });
  await assert.rejects(mail.createSpamFilter(u, 'a@b.c')); assert.equal(withTokens(u).accessToken, 'NEW');
});
test('tokens: column sealing is idempotent; another key cannot open them', () => {
  const s = sealColumn('ya29'); assert.equal(sealColumn(s), s); assert.equal(sealColumn(null), null);
  const box = sealUserTokens({ id: 'g', accessToken: 'A' }).tokenBox;
  const old = { s: process.env.SESSION_SECRET, k: process.env.MAIL_ENCRYPTION_KEY };
  process.env.SESSION_SECRET = 'other'; delete process.env.MAIL_ENCRYPTION_KEY;
  try { assert.throws(() => withTokens({ tokenBox: box })); }
  finally { process.env.SESSION_SECRET = old.s; if (old.k) process.env.MAIL_ENCRYPTION_KEY = old.k; }
});
