// ============================================================
// services/mail/gmailProvider.js — Gmail (Google OAuth)
// ------------------------------------------------------------
// Thin adapter over the original services/gmailService.js so the
// existing, tested Gmail behaviour stays exactly the same.
// ============================================================
const gmail = require('../gmailService');

const name  = 'google';
const label = 'Gmail';
const hasServerFilters = true;   // Gmail filters block future mail server-side

// Both tokens, so an expired access token is refreshed automatically
const tok = (user) => user.refreshToken ? { access_token: user.accessToken, refresh_token: user.refreshToken } : user.accessToken;

function fetchEmails(user, maxResults) {
  return gmail.fetchEmails(tok(user), maxResults, user.id);
}

function searchEmails(user, query, maxResults) {
  return gmail.searchEmails(tok(user), query, maxResults, user.id);
}

function sendReply(user, to, subject, body, threadOptions = {}) {
  return gmail.sendReply(tok(user), to, subject, body, threadOptions);
}

function moveToSpam(user, messageId)        { return gmail.moveToSpam(tok(user), messageId); }
function removeFromSpam(user, messageId)    { return gmail.removeFromSpam(tok(user), messageId); }
function createSpamFilter(user, senderEmail) { return gmail.createSpamFilter(tok(user), senderEmail); }

// Newest genuine reply from `sender` in the INBOX after `afterMs`.
// (This is the honeypot poll logic that used to live in routes/honeypot.js.)
async function findLatestFrom(user, sender, { afterMs = 0, skipId = null } = {}) {
  const client    = gmail.getGmailClient(tok(user));
  const senderRaw = String(sender || '').replace(/.*<(.+)>/, '$1').trim();
  const myEmail   = (user.email || '').toLowerCase();

  const searchRes = await client.users.messages.list({
    userId: 'me', q: `from:${senderRaw} in:inbox -in:sent`, maxResults: 10
  });

  let latest = null;
  let latestTs = 0;
  for (const msg of searchRes.data.messages || []) {
    if (msg.id === skipId) continue;
    const detail = await client.users.messages.get({
      userId: 'me', id: msg.id, format: 'metadata', metadataHeaders: ['From', 'Date']
    });
    // Our own outgoing replies carry the SENT label — never treat them as the scammer's
    if ((detail.data.labelIds || []).includes('SENT')) continue;
    const fromHeader = (detail.data.payload?.headers?.find(h => h.name.toLowerCase() === 'from')?.value || '').toLowerCase();
    if (myEmail && fromHeader.includes(myEmail)) continue;
    const ts = parseInt(detail.data.internalDate || '0', 10);
    if (ts > afterMs && ts > latestTs) { latestTs = ts; latest = detail.data; }
  }
  if (!latest) return null;

  // Full body (first 600 chars) + Message-ID for In-Reply-To threading
  let text = latest.snippet || '';
  let messageId = '';
  try {
    const full  = await client.users.messages.get({ userId: 'me', id: latest.id, format: 'full' });
    const parts = full.data.payload?.parts || [];
    const tp    = parts.find(p => p.mimeType === 'text/plain');
    text = tp?.body?.data
      ? Buffer.from(tp.body.data, 'base64').toString('utf-8').substring(0, 600)
      : (full.data.snippet || text);
    const hdrs = full.data.payload?.headers || [];
    messageId  = (hdrs.find(h => h.name.toLowerCase() === 'message-id') || {}).value || '';
  } catch (_) { /* keep snippet */ }

  return { id: latest.id, threadId: latest.threadId, messageId, text, timestamp: latestTs };
}

// Forward the original email, untouched, as an attachment (what anti-phishing groups ask for)
async function forwardAsAttachment(user, messageId, to, note) {
  const client = gmail.getGmailClient(tok(user));
  const raw = (await client.users.messages.get({ userId: 'me', id: messageId, format: 'raw' })).data.raw;
  const original = Buffer.from(String(raw).replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  const boundary = 'gj-' + Date.now().toString(36);
  const mime = [
    `To: ${to}`, 'Subject: Phishing report (forwarded by Genjutsu)', 'MIME-Version: 1.0',
    `Content-Type: multipart/mixed; boundary="${boundary}"`, '',
    `--${boundary}`, 'Content-Type: text/plain; charset=utf-8', '', note, '',
    `--${boundary}`, 'Content-Type: message/rfc822', 'Content-Disposition: attachment; filename="phishing.eml"', '',
    original.toString('utf8'), `--${boundary}--`, ''
  ].join('\r\n');
  await client.users.messages.send({ userId: 'me', requestBody: { raw: Buffer.from(mime).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') } });
}

async function getAttachment(user, email, att) {
  if (att._content) return att._content;
  if (!att.attachmentId) return null;
  return gmail.getAttachment(tok(user), email.id, att.attachmentId);
}

module.exports = {
  name, label, hasServerFilters, getAttachment,
  fetchEmails, searchEmails, sendReply, moveToSpam, removeFromSpam, createSpamFilter, findLatestFrom, forwardAsAttachment
};
