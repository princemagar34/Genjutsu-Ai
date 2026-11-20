// ============================================================
// services/mail/outlookProvider.js — Outlook / Hotmail / Live /
// Microsoft 365 via Microsoft Graph (OAuth 2.0)
// ------------------------------------------------------------
// Uses immutable message IDs (Prefer: IdType="ImmutableId") so an
// email keeps the same ID when it is moved to Junk and back —
// that is what block / unblock rely on.
// ============================================================
const AUTH_BASE = (process.env.MS_AUTH_BASE  || 'https://login.microsoftonline.com/common/oauth2/v2.0').replace(/\/$/, '');
const GRAPH     = (process.env.MS_GRAPH_BASE || 'https://graph.microsoft.com/v1.0').replace(/\/$/, '');
const SCOPES    = 'openid profile email offline_access User.Read Mail.ReadWrite Mail.Send MailboxSettings.ReadWrite';

const name  = 'microsoft';
const label = 'Outlook';
const hasServerFilters = true;   // Outlook inbox rules block future mail server-side

const LIST_FIELDS = [
  'id', 'conversationId', 'internetMessageId', 'subject', 'from', 'toRecipients', 'replyTo',
  'receivedDateTime', 'bodyPreview', 'body', 'hasAttachments', 'isRead', 'internetMessageHeaders'
].join(',');

// ── OAuth helpers ────────────────────────────────────────────
function isConfigured() {
  return Boolean(process.env.MICROSOFT_CLIENT_ID && process.env.MICROSOFT_CLIENT_SECRET && process.env.MICROSOFT_CALLBACK_URL);
}

function authUrl(state) {
  const p = new URLSearchParams({
    client_id:     process.env.MICROSOFT_CLIENT_ID,
    response_type: 'code',
    redirect_uri:  process.env.MICROSOFT_CALLBACK_URL,
    response_mode: 'query',
    scope:         SCOPES,
    state,
    prompt:        'select_account'
  });
  return `${AUTH_BASE}/authorize?${p}`;
}

async function tokenRequest(params) {
  const res = await fetch(`${AUTH_BASE}/token`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body:    new URLSearchParams({
      client_id:     process.env.MICROSOFT_CLIENT_ID,
      client_secret: process.env.MICROSOFT_CLIENT_SECRET,
      scope:         SCOPES,
      ...params
    })
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || !data.access_token) {
    throw new Error(`Microsoft token request failed: ${data.error_description || data.error || res.status}`);
  }
  return data;
}

function exchangeCode(code) {
  return tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: process.env.MICROSOFT_CALLBACK_URL });
}

async function getProfile(accessToken) {
  const res = await fetch(`${GRAPH}/me?$select=id,displayName,mail,userPrincipalName`, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  if (!res.ok) throw new Error(`Could not read Microsoft profile (${res.status})`);
  return res.json();
}

// Access tokens last ~1 hour. On a 401 we refresh once and update the
// session user object in place so the new token is saved with the session.
async function refresh(user) {
  if (!user.refreshToken) throw new Error('Outlook session expired — please sign in with Microsoft again');
  const data = await tokenRequest({ grant_type: 'refresh_token', refresh_token: user.refreshToken });
  user.accessToken = data.access_token;
  if (data.refresh_token) user.refreshToken = data.refresh_token;
}

// ── Graph request wrapper ────────────────────────────────────
async function graph(user, method, path, body) {
  const send = () => fetch(`${GRAPH}${path}`, {
    method,
    headers: {
      Authorization:  `Bearer ${user.accessToken}`,
      'Content-Type': 'application/json',
      Prefer:         'IdType="ImmutableId", outlook.body-content-type="text"'
    },
    body: body ? JSON.stringify(body) : undefined
  });

  let res = await send();
  if (res.status === 401 && user.refreshToken) {
    await refresh(user);
    res = await send();
  }
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    const err = new Error(`Outlook ${method} ${path.split('?')[0]} failed (${res.status}): ${detail?.error?.message || res.statusText}`);
    err.status = res.status;
    throw err;
  }
  if (res.status === 202 || res.status === 204) return null;
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

// ── Helpers ──────────────────────────────────────────────────
function plainAddress(value) {
  const m = String(value || '').match(/<([^>]+)>/) || String(value || '').match(/([^\s<>"]+@[^\s<>"]+)/);
  return m ? m[1].trim() : String(value || '').trim();
}

function formatAddress(ea) {
  if (!ea || !ea.address) return '';
  return ea.name && ea.name !== ea.address ? `${ea.name} <${ea.address}>` : ea.address;
}

function normalise(m, attachments = []) {
  const headers = m.internetMessageHeaders || [];
  const get = (n) => (headers.find(h => h.name.toLowerCase() === n) || {}).value || '';
  const body = m.body?.content || '';
  return {
    id:        m.id,
    threadId:  m.conversationId,
    messageId: m.internetMessageId || get('message-id') || null,
    subject:   m.subject || '(No Subject)',
    from:      formatAddress(m.from?.emailAddress),
    to:        (m.toRecipients || []).map(r => formatAddress(r.emailAddress)).join(', '),
    replyTo:   (m.replyTo || []).length ? formatAddress(m.replyTo[0].emailAddress) : null,
    date:      m.receivedDateTime,
    snippet:   m.bodyPreview || '',
    body,
    links:     [...body.matchAll(/https?:\/\/[^\s<>")\]]+/g)].map(x => x[0]),
    labels:    m.isRead ? ['INBOX'] : ['INBOX', 'UNREAD'],
    attachments,
    // SPF / DKIM / DMARC come straight from the original message headers,
    // so threatService's authentication layer works unchanged.
    authResults:    get('authentication-results'),
    received:       headers.filter(h => h.name.toLowerCase() === 'received').map(h => h.value),
    xOriginatingIp: get('x-originating-ip'),
    receivedSpf:    get('received-spf'),
    arcAuthResults: get('arc-authentication-results'),
    html:            '',                       // Graph returns the text version (Prefer header)
    listUnsubscribe: get('list-unsubscribe') || null,
    listId:          get('list-id') || null
  };
}

async function listAttachments(user, messageId) {
  try {
    const data = await graph(user, 'GET', `/me/messages/${encodeURIComponent(messageId)}/attachments?$select=name,contentType,size`);
    return (data?.value || []).map(a => ({
      filename: a.name || 'unnamed', mimeType: a.contentType || 'application/octet-stream',
      size: a.size || 0, attachmentId: a.id || null
    }));
  } catch (_) { return []; }
}

async function getAttachment(user, email, att) {
  if (!att.attachmentId) return null;
  const a = await graph(user, 'GET', `/me/messages/${encodeURIComponent(email.id)}/attachments/${encodeURIComponent(att.attachmentId)}`);
  return a?.contentBytes ? Buffer.from(a.contentBytes, 'base64') : null;
}

// ── Provider operations ──────────────────────────────────────
async function fetchEmails(user, maxResults = 20) {
  const top  = Math.max(1, Math.min(parseInt(maxResults, 10) || 20, 500));
  const data = await graph(user, 'GET',
    `/me/mailFolders/inbox/messages?$top=${top}&$orderby=receivedDateTime desc&$select=${LIST_FIELDS}`);
  const messages = data?.value || [];
  return Promise.all(messages.map(async m =>
    normalise(m, m.hasAttachments ? await listAttachments(user, m.id) : [])));
}

// Search the whole mailbox with Microsoft Graph's $search (sender, subject, body).
// $search can't be combined with $orderby, so results are sorted here. Sent
// items and drafts are dropped so only received mail is checked.
async function searchEmails(user, query, maxResults = 50) {
  const top  = Math.max(1, Math.min(parseInt(maxResults, 10) || 50, 100));
  const term = String(query || '').replace(/["\\]/g, ' ').trim();
  if (!term) return [];
  const data = await graph(user, 'GET',
    `/me/messages?$search=${encodeURIComponent(`"${term}"`)}&$top=${top}&$select=${LIST_FIELDS},isDraft,parentFolderId`);
  let sentId = null;
  try { sentId = (await graph(user, 'GET', '/me/mailFolders/sentitems?$select=id'))?.id || null; } catch (_) {}
  const messages = (data?.value || []).filter(m => !m.isDraft && m.parentFolderId !== sentId);
  const emails = await Promise.all(messages.map(async m =>
    normalise(m, m.hasAttachments ? await listAttachments(user, m.id) : [])));
  return emails.sort((a, b) => new Date(b.date) - new Date(a.date));
}

// Replies inside the original conversation when we know which message we
// are answering (honeypot), otherwise sends a fresh message.
async function sendReply(user, to, subject, body, threadOptions = {}) {
  const recipients = [{ emailAddress: { address: plainAddress(to) } }];
  if (threadOptions.replyToMessageId) {
    try {
      await graph(user, 'POST', `/me/messages/${encodeURIComponent(threadOptions.replyToMessageId)}/reply`, {
        message: { toRecipients: recipients },
        comment: body
      });
      return;
    } catch (err) {
      if (err.status !== 404) throw err;   // original deleted/moved away → fall back to a new message
    }
  }
  await graph(user, 'POST', '/me/sendMail', {
    message: { subject, body: { contentType: 'Text', content: body }, toRecipients: recipients },
    saveToSentItems: true
  });
}

function moveToSpam(user, messageId) {
  return graph(user, 'POST', `/me/messages/${encodeURIComponent(messageId)}/move`, { destinationId: 'junkemail' });
}

function removeFromSpam(user, messageId) {
  return graph(user, 'POST', `/me/messages/${encodeURIComponent(messageId)}/move`, { destinationId: 'inbox' });
}

// Inbox rule = Outlook's equivalent of a Gmail filter
async function createSpamFilter(user, senderEmail) {
  const address = plainAddress(senderEmail);
  if (!address.includes('@')) return;
  const junk = await graph(user, 'GET', '/me/mailFolders/junkemail?$select=id');
  await graph(user, 'POST', '/me/mailFolders/inbox/messageRules', {
    displayName: `Genjutsu block: ${address}`.slice(0, 255),
    sequence:    1,
    isEnabled:   true,
    conditions:  { fromAddresses: [{ emailAddress: { address } }] },
    actions:     { moveToFolder: junk.id, stopProcessingRules: true }
  });
}

async function findLatestFrom(user, sender, { afterMs = 0, skipId = null } = {}) {
  const address = plainAddress(sender).replace(/'/g, "''");
  const since   = new Date(Math.max(0, afterMs)).toISOString();
  const filter  = encodeURIComponent(`receivedDateTime ge ${since} and from/emailAddress/address eq '${address}'`);
  const data    = await graph(user, 'GET',
    `/me/mailFolders/inbox/messages?$filter=${filter}&$top=10&$select=id,conversationId,internetMessageId,from,receivedDateTime,body,bodyPreview`);

  const myEmail = (user.email || '').toLowerCase();
  const candidates = (data?.value || [])
    .filter(m => m.id !== skipId)
    .filter(m => (m.from?.emailAddress?.address || '').toLowerCase() !== myEmail)
    .map(m => ({ m, ts: new Date(m.receivedDateTime).getTime() }))
    .filter(x => x.ts > afterMs)
    .sort((a, b) => b.ts - a.ts);

  if (!candidates.length) return null;
  const { m, ts } = candidates[0];
  return {
    id: m.id, threadId: m.conversationId, messageId: m.internetMessageId || '',
    text: (m.body?.content || m.bodyPreview || '').substring(0, 600), timestamp: ts
  };
}

// Forward the original email to a reporting address
async function forwardAsAttachment(user, messageId, to, note) {
  await graph(user, 'POST', `/me/messages/${encodeURIComponent(messageId)}/forward`, {
    comment: note, toRecipients: [{ emailAddress: { address: to } }]
  });
}

module.exports = {
  getAttachment,
  name, label, hasServerFilters,
  isConfigured, authUrl, exchangeCode, getProfile,
  fetchEmails, searchEmails, sendReply, moveToSpam, removeFromSpam, createSpamFilter, findLatestFrom, forwardAsAttachment
};
