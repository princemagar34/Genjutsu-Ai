// ============================================================
// services/mail/imapProvider.js — Yahoo, iCloud, AOL, Zoho, GMX,
// Yandex and any custom mailbox via IMAP (read) + SMTP (send)
// ------------------------------------------------------------
// Signs in with the user's email address + an APP PASSWORD.
// Credentials are sealed with AES-256-GCM (see secretBox.js).
// IMAP has no portable "filter" API, so sender blocking is enforced
// by Genjutsu itself on every scan (see services/mail/index.js).
// ============================================================
const dns              = require('dns').promises;
const net              = require('net');
const { ImapFlow }     = require('imapflow');
const { simpleParser } = require('mailparser');
const nodemailer       = require('nodemailer');
const { open }         = require('./secretBox');

const name  = 'imap';
const label = 'Email (IMAP)';
const hasServerFilters = false;

// Official server settings. `domains` lets us refuse a custom server for
// these well-known domains (stops someone pointing "victim@gmail.com" at
// a fake server they control).
const PRESETS = {
  yahoo:  { label: 'Yahoo Mail',  domains: ['yahoo.com', 'ymail.com', 'rocketmail.com'],
            imap: { host: 'imap.mail.yahoo.com', port: 993, secure: true },
            smtp: { host: 'smtp.mail.yahoo.com', port: 465, secure: true },
            help: 'Yahoo Account Security → Generate app password' },
  icloud: { label: 'iCloud Mail', domains: ['icloud.com', 'me.com', 'mac.com'],
            imap: { host: 'imap.mail.me.com', port: 993, secure: true },
            smtp: { host: 'smtp.mail.me.com', port: 587, secure: false },
            help: 'appleid.apple.com → Sign-In and Security → App-Specific Passwords' },
  aol:    { label: 'AOL Mail',    domains: ['aol.com'],
            imap: { host: 'imap.aol.com', port: 993, secure: true },
            smtp: { host: 'smtp.aol.com', port: 465, secure: true },
            help: 'AOL Account Security → Generate app password' },
  zoho:   { label: 'Zoho Mail',   domains: ['zoho.com', 'zohomail.com'],
            imap: { host: 'imap.zoho.com', port: 993, secure: true },
            smtp: { host: 'smtp.zoho.com', port: 465, secure: true },
            help: 'Zoho Mail → Settings → enable IMAP, then create an app password' },
  gmx:    { label: 'GMX Mail',    domains: ['gmx.com', 'gmx.net', 'gmx.de'],
            imap: { host: 'imap.gmx.com', port: 993, secure: true },
            smtp: { host: 'mail.gmx.com', port: 465, secure: true },
            help: 'GMX → Settings → POP3 & IMAP → enable access' },
  yandex: { label: 'Yandex Mail', domains: ['yandex.com', 'yandex.ru'],
            imap: { host: 'imap.yandex.com', port: 993, secure: true },
            smtp: { host: 'smtp.yandex.com', port: 465, secure: true },
            help: 'Yandex ID → Security → App passwords' }
};

// Domains that must use their own sign-in, never a custom IMAP server
const RESERVED_DOMAINS = new Set([
  'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
  ...Object.values(PRESETS).flatMap(p => p.domains)
]);

const ALLOWED_PORTS = new Set([143, 993, 25, 465, 587, 2525]);

function publicPresets() {
  return Object.entries(PRESETS).map(([id, p]) => ({ id, label: p.label, help: p.help }));
}

function domainOf(email) { return String(email || '').split('@').pop().toLowerCase(); }

// Build + validate the connection settings for a login attempt
function buildCredentials({ provider = 'custom', email, password, imapHost, imapPort, imapSecure, smtpHost, smtpPort, smtpSecure }) {
  email = String(email || '').trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error('Enter a valid email address');
  if (!password) throw new Error('Enter your app password');

  const domain = domainOf(email);
  if (['gmail.com', 'googlemail.com'].includes(domain)) throw new Error('Gmail addresses: please use "Continue with Google"');
  if (['outlook.com', 'hotmail.com', 'live.com', 'msn.com'].includes(domain)) throw new Error('Outlook/Hotmail addresses: please use "Continue with Microsoft"');

  if (provider !== 'custom') {
    const preset = PRESETS[provider];
    if (!preset) throw new Error('Unknown email provider');
    return { provider, email, password, imap: { ...preset.imap }, smtp: { ...preset.smtp } };
  }

  if (RESERVED_DOMAINS.has(domain)) throw new Error('This address belongs to a provider in the list above — please choose it there');
  const iPort = parseInt(imapPort, 10) || 993;
  const sPort = parseInt(smtpPort, 10) || 465;
  if (!imapHost || !smtpHost) throw new Error('Enter both the IMAP and SMTP server names');
  const testing = process.env.ALLOW_PRIVATE_MAIL_HOSTS === 'true';   // local testing only
  if (!testing && (!ALLOWED_PORTS.has(iPort) || !ALLOWED_PORTS.has(sPort))) throw new Error('Unsupported mail server port');
  return {
    provider: 'custom', email, password,
    imap: { host: String(imapHost).trim(), port: iPort, secure: imapSecure !== undefined ? Boolean(imapSecure) : iPort === 993 },
    smtp: { host: String(smtpHost).trim(), port: sPort, secure: smtpSecure !== undefined ? Boolean(smtpSecure) : sPort === 465 }
  };
}

// ── SSRF guard: custom servers must resolve to public addresses ──
function isPrivateAddress(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31)
        || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  const v = ip.toLowerCase();
  if (v.startsWith('::ffff:')) return isPrivateAddress(v.slice(7));
  return v === '::1' || v === '::' || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe80');
}

async function assertPublicHost(host) {
  if (process.env.ALLOW_PRIVATE_MAIL_HOSTS === 'true') return;   // local testing only
  const addrs = net.isIP(host) ? [{ address: host }] : await dns.lookup(host, { all: true });
  if (!addrs.length || addrs.some(a => isPrivateAddress(a.address))) {
    throw new Error(`Mail server ${host} is not a public internet address`);
  }
}

// ── Connections ──────────────────────────────────────────────
function credsOf(user) { return open(user.mailCreds); }

function imapClient(creds) {
  return new ImapFlow({
    host: creds.imap.host, port: creds.imap.port, secure: creds.imap.secure,
    auth: { user: creds.email, pass: creds.password },
    logger: false, emitLogs: false,
    connectionTimeout: 20000, greetingTimeout: 15000, socketTimeout: 60000
  });
}

async function withImap(creds, fn) {
  if (creds.provider === 'custom') await assertPublicHost(creds.imap.host);
  const client = imapClient(creds);
  await client.connect();
  try { return await fn(client); }
  finally { await client.logout().catch(() => client.close()); }
}

function smtpTransport(creds) {
  return nodemailer.createTransport({
    host: creds.smtp.host, port: creds.smtp.port, secure: creds.smtp.secure,
    requireTLS: !creds.smtp.secure && process.env.ALLOW_PRIVATE_MAIL_HOSTS !== 'true',
    auth: { user: creds.email, pass: creds.password },
    connectionTimeout: 20000
  });
}

// Used at sign-in: proves the address + app password really work
async function verify(creds) {
  await withImap(creds, async () => {});
  if (creds.provider === 'custom') await assertPublicHost(creds.smtp.host);
  await smtpTransport(creds).verify();
}

// ── Message IDs ──────────────────────────────────────────────
// UIDs change when a message moves folder, so the ID we hand out is the
// Message-ID header (base64url). That lets block/unblock find the same
// message in INBOX or Junk later.
function toId(messageId, uid) {
  return messageId ? 'm' + Buffer.from(messageId).toString('base64url') : 'u' + uid;
}
function fromId(id) {
  const s = String(id || '');
  if (s.startsWith('m')) return { messageId: Buffer.from(s.slice(1), 'base64url').toString('utf8') };
  if (s.startsWith('u')) return { uid: parseInt(s.slice(1), 10) };
  throw new Error('Invalid message id');
}

async function findUids(client, id) {
  const ref = fromId(id);
  if (ref.uid) return [ref.uid];
  const uids = await client.search({ header: { 'message-id': ref.messageId } }, { uid: true });
  return uids || [];
}

async function junkPath(client) {
  const boxes = await client.list();
  const byUse = boxes.find(b => b.specialUse === '\\Junk');
  if (byUse) return byUse.path;
  const byName = boxes.find(b => /^(junk|spam|bulk mail|junk e-mail|junk email)$/i.test(b.name));
  if (byName) return byName.path;
  await client.mailboxCreate('Junk');
  return 'Junk';
}

// ── Parsing ──────────────────────────────────────────────────
function rawHeader(parsed, key) {
  return (parsed.headerLines || [])
    .filter(h => h.key === key)
    .map(h => h.line.replace(/^[^:]+:\s*/, '').replace(/\r?\n\s+/g, ' '))
    .join('\n');
}

async function normalise(msg) {
  const p    = await simpleParser(msg.source);
  const refs = Array.isArray(p.references) ? p.references : (p.references ? String(p.references).split(/\s+/) : []);
  const { htmlToText, linksFromHtml } = require('../detection');
  const html = typeof p.html === 'string' ? p.html : '';
  const body = p.text || htmlToText(html);
  return {
    id:        toId(p.messageId, msg.uid),
    threadId:  refs[0] || p.inReplyTo || p.messageId || toId(p.messageId, msg.uid),
    messageId: p.messageId || null,
    subject:   p.subject || '(No Subject)',
    from:      p.from?.text || '',
    to:        p.to?.text || '',
    replyTo:   p.replyTo?.text || null,
    date:      (p.date || msg.internalDate || new Date()).toISOString(),
    snippet:   body.replace(/\s+/g, ' ').trim().slice(0, 200),
    body,
    links:     [...new Set([...[...body.matchAll(/https?:\/\/[^\s<>")\]]+/g)].map(x => x[0]), ...linksFromHtml(html)])],
    labels:    msg.flags && msg.flags.has('\\Seen') ? ['INBOX'] : ['INBOX', 'UNREAD'],
    attachments: (p.attachments || []).map(a => {
      const att = { filename: a.filename || 'unnamed', mimeType: a.contentType || 'application/octet-stream', size: a.size || 0, attachmentId: null };
      if (a.content) Object.defineProperty(att, '_content', { value: a.content, enumerable: false });   // for the attachment check only
      return att;
    }),
    authResults:    rawHeader(p, 'authentication-results'),
    received:       (p.headerLines || []).filter(h => h.key === 'received').map(h => h.line.replace(/^[^:]+:\s*/, '').replace(/\r?\n\s+/g, ' ')),
    xOriginatingIp: rawHeader(p, 'x-originating-ip'),
    receivedSpf:    rawHeader(p, 'received-spf'),
    arcAuthResults: rawHeader(p, 'arc-authentication-results'),
    fromAddress:    (p.from?.value?.[0]?.address || '').toLowerCase(),
    html,
    listUnsubscribe: rawHeader(p, 'list-unsubscribe') || null,
    listId:          rawHeader(p, 'list-id') || null
  };
}

const MAX_SOURCE = 2 * 1024 * 1024;   // read at most 2 MB of each message

// ── Provider operations ──────────────────────────────────────
async function fetchEmails(user, maxResults = 20) {
  const max = Math.max(1, Math.min(parseInt(maxResults, 10) || 20, 500));
  return withImap(credsOf(user), async (client) => {
    const lock = await client.getMailboxLock('INBOX');
    try {
      const total = client.mailbox.exists;
      if (!total) return [];
      const range = `${Math.max(1, total - max + 1)}:*`;
      const raw = [];
      for await (const msg of client.fetch(range, { uid: true, flags: true, internalDate: true, source: { maxLength: MAX_SOURCE } })) {
        raw.push(msg);
      }
      const emails = [];
      for (const msg of raw) {
        try { emails.push(await normalise(msg)); } catch (_) { /* skip unparsable */ }
      }
      return emails.sort((a, b) => new Date(b.date) - new Date(a.date));
    } finally { lock.release(); }
  });
}

async function sendReply(user, to, subject, body, threadOptions = {}) {
  const creds = credsOf(user);
  if (creds.provider === 'custom') await assertPublicHost(creds.smtp.host);
  await smtpTransport(creds).sendMail({
    from: creds.email, to, subject, text: body,
    inReplyTo:  threadOptions.inReplyTo  || undefined,
    references: threadOptions.references || threadOptions.inReplyTo || undefined
  });
}

async function moveToSpam(user, id) {
  return withImap(credsOf(user), async (client) => {
    const junk = await junkPath(client);
    const lock = await client.getMailboxLock('INBOX');
    try {
      const uids = await findUids(client, id);
      if (!uids.length) throw new Error('Email not found in inbox');
      await client.messageMove(uids, junk, { uid: true });
    } finally { lock.release(); }
  });
}

async function removeFromSpam(user, id) {
  return withImap(credsOf(user), async (client) => {
    const junk = await junkPath(client);
    const lock = await client.getMailboxLock(junk);
    try {
      const uids = await findUids(client, id);
      if (!uids.length) throw new Error('Email not found in junk folder');
      await client.messageMove(uids, 'INBOX', { uid: true });
    } finally { lock.release(); }
  });
}

// No server-side filters over IMAP — index.js enforces blocked senders on each scan
async function createSpamFilter() { return { emulated: true }; }

async function findLatestFrom(user, sender, { afterMs = 0, skipId = null } = {}) {
  const address = String(sender || '').replace(/.*<(.+)>/, '$1').trim().toLowerCase();
  const myEmail = (user.email || '').toLowerCase();
  return withImap(credsOf(user), async (client) => {
    const lock = await client.getMailboxLock('INBOX');
    try {
      // IMAP SINCE has day granularity — search a day back, then filter exactly
      const uids = await client.search({ from: address, since: new Date(Math.max(0, afterMs - 86400000)) }, { uid: true });
      if (!uids || !uids.length) return null;
      let latest = null;
      for await (const msg of client.fetch(uids.slice(-10), { uid: true, internalDate: true, source: { maxLength: MAX_SOURCE } }, { uid: true })) {
        let email;
        try { email = await normalise(msg); } catch (_) { continue; }
        const ts = new Date(email.date).getTime();
        if (email.id === skipId || email.fromAddress === myEmail || ts <= afterMs) continue;
        if (!latest || ts > latest.timestamp) {
          latest = { id: email.id, threadId: email.threadId, messageId: email.messageId || '', text: email.body.substring(0, 600), timestamp: ts };
        }
      }
      return latest;
    } finally { lock.release(); }
  });
}

// Forward the original email (raw source) as an attachment
async function forwardAsAttachment(user, id, to, note) {
  const creds = credsOf(user);
  const source = await withImap(creds, async (client) => {
    for (const box of ['INBOX', await junkPath(client)]) {
      const lock = await client.getMailboxLock(box);
      try {
        const uids = await findUids(client, id);
        if (uids.length) {
          const msg = await client.fetchOne(uids[0], { source: true }, { uid: true });
          if (msg && msg.source) return msg.source;
        }
      } finally { lock.release(); }
    }
    return null;
  });
  if (!source) throw new Error('Email not found');
  if (creds.provider === 'custom') await assertPublicHost(creds.smtp.host);
  await smtpTransport(creds).sendMail({
    from: creds.email, to, subject: 'Phishing report (forwarded by Genjutsu)', text: note,
    attachments: [{ filename: 'phishing.eml', content: source, contentType: 'message/rfc822' }]
  });
}

module.exports = {
  getAttachment: async (user, email, att) => att._content || null,
  name, label, hasServerFilters, PRESETS,
  publicPresets, buildCredentials, verify, isPrivateAddress,
  fetchEmails, sendReply, moveToSpam, removeFromSpam, createSpamFilter, findLatestFrom, forwardAsAttachment
};
