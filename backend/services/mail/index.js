// ============================================================
// services/mail/index.js — one mail API for every provider
// ------------------------------------------------------------
// Routes call these functions with the signed-in session user.
// user.provider picks the back-end:
//   'google'    → Gmail API            (gmailProvider.js)
//   'microsoft' → Microsoft Graph      (outlookProvider.js)
//   'imap'      → IMAP + SMTP          (imapProvider.js)
// Users created before multi-provider support have no provider
// field and are treated as Gmail, so nothing changes for them.
// ============================================================
const providers = {
  google:    require('./gmailProvider'),
  microsoft: require('./outlookProvider'),
  imap:      require('./imapProvider'),
  demo:      require('./demoProvider')
};

const { withTokens, persistTokens } = require('./tokens');

const NO_REPLY = /no.?reply|noreply|postmaster|mailer.daemon|do.not.reply/i;

// Run a provider call with the user's tokens opened in memory only.
// If the provider refreshed a token (Outlook does), the new one is
// sealed back onto the session user so it is saved encrypted.
async function withMailbox(user, fn) {
  const ctx = withTokens(user);
  try {
    return await fn(ctx);
  } finally {
    persistTokens(user, ctx);
  }
}

function providerFor(user) {
  const key = (user && user.provider) || 'google';
  const provider = providers[key];
  if (!provider) throw new Error(`Unsupported mail provider: ${key}`);
  return provider;
}

function providerLabel(user) {
  if (user && user.provider === 'imap' && user.mailProvider) {
    const preset = providers.imap.PRESETS[user.mailProvider];
    if (preset) return preset.label;
  }
  return providerFor(user).label;
}

function senderAddress(from) {
  return String(from || '').toLowerCase().replace(/.*<(.+)>/, '$1').trim();
}

// IMAP has no server-side filters, so blocked senders are enforced here:
// new mail from a blocked sender is moved to Junk and hidden from the scan.
async function enforceBlockedSenders(user, provider, emails) {
  const { getBlockedEmails } = require('../../database/db');
  let rows = [];
  try { rows = await getBlockedEmails(user.id); } catch (_) { return emails; }
  const blocked = new Set(rows.map(r => senderAddress(r.sender_email)).filter(Boolean));
  if (!blocked.size) return emails;

  const kept = [];
  for (const email of emails) {
    if (blocked.has(senderAddress(email.from))) {
      try { await provider.moveToSpam(user, email.id); } catch (_) { /* already moved */ }
    } else {
      kept.push(email);
    }
  }
  return kept;
}

async function fetchEmails(user, maxResults = 20) {
  const provider = providerFor(user);
  return withMailbox(user, async ctx => {
    const emails = await provider.fetchEmails(ctx, maxResults);
    return provider.hasServerFilters ? emails : enforceBlockedSenders(ctx, provider, emails);
  });
}

// One attachment's bytes, for the attachment check (null when the provider can't give them)
async function getAttachment(user, email, att) {
  const provider = providerFor(user);
  if (!provider.getAttachment) return null;
  return withMailbox(user, ctx => provider.getAttachment(ctx, email, att));
}

// threadOptions: { threadId, inReplyTo, references, replyToMessageId }
async function sendReply(user, to, subject, body, threadOptions = {}) {
  if (!to || NO_REPLY.test(to)) {
    console.warn(`[Honeypot] Blocked reply to no-reply address: ${to}`);
    const err = new Error('NO_REPLY_ADDRESS');
    err.noReply = true;
    err.blockedAddress = to;
    throw err;
  }
  return withMailbox(user, ctx => providerFor(user).sendReply(ctx, to, subject, body, threadOptions));
}

const moveToSpam       = (user, id)     => withMailbox(user, ctx => providerFor(user).moveToSpam(ctx, id));
const removeFromSpam   = (user, id)     => withMailbox(user, ctx => providerFor(user).removeFromSpam(ctx, id));
const createSpamFilter = (user, sender) => withMailbox(user, ctx => providerFor(user).createSpamFilter(ctx, sender));
const findLatestFrom   = (user, sender, opts) => withMailbox(user, ctx => providerFor(user).findLatestFrom(ctx, sender, opts));
const forwardAsAttachment = (user, id, to, note) => withMailbox(user, ctx => providerFor(user).forwardAsAttachment(ctx, id, to, note));
// Send an email to the signed-in user's own address (weekly digest)
const sendToSelf = (user, subject, body) => withMailbox(user, ctx => providerFor(user).sendReply(ctx, user.email, subject, body, {}));

module.exports = {
  getAttachment,
  providers, providerFor, providerLabel,
  fetchEmails, sendReply, moveToSpam, removeFromSpam, createSpamFilter, findLatestFrom,
  forwardAsAttachment, sendToSelf, withMailbox
};
