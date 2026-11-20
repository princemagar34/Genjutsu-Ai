// ============================================================
// services/gmailService.js — All Gmail API operations
// ============================================================
const { google } = require('googleapis');

function getGmailClient(accessToken) {
    const auth = new google.auth.OAuth2(
        process.env.GOOGLE_CLIENT_ID,
        process.env.GOOGLE_CLIENT_SECRET,
        process.env.GOOGLE_CALLBACK_URL
    );
    // accessToken may be a string, or { access_token, refresh_token } so googleapis
    // can renew an expired access token by itself (needed for background jobs)
    auth.setCredentials(typeof accessToken === 'object' && accessToken ? accessToken : { access_token: accessToken });
    return google.gmail({ version: 'v1', auth });
}

// ── Parsed-message cache ─────────────────────────────────────
// The inbox is re-read every minute while the dashboard is open. Listing the
// newest message IDs is one cheap call; downloading each full message is the
// expensive part, so a message is downloaded once and then reused. Entries are
// keyed by mailbox owner + message ID and capped so memory stays small on the
// free server. Callers get a copy, because later steps add fields to emails.
const DETAIL_CACHE_MAX = 3000;
const detailCache = new Map();   // `${owner}:${id}` -> parsed email

function cacheGet(key) {
    const hit = detailCache.get(key);
    if (!hit) return null;
    detailCache.delete(key); detailCache.set(key, hit);   // mark as recently used
    return structuredClone(hit);
}
function cacheSet(key, value) {
    detailCache.set(key, value);
    while (detailCache.size > DETAIL_CACHE_MAX) detailCache.delete(detailCache.keys().next().value);
}

// Download full messages, 10 at a time, skipping ones already cached
async function getDetails(gmail, ids, owner) {
    const out = new Array(ids.length);
    const todo = [];
    ids.forEach((id, i) => {
        const hit = owner ? cacheGet(`${owner}:${id}`) : null;
        if (hit) out[i] = hit; else todo.push(i);
    });
    for (let k = 0; k < todo.length; k += 10) {
        await Promise.all(todo.slice(k, k + 10).map(async (i) => {
            const detail = await gmail.users.messages.get({ userId: 'me', id: ids[i], format: 'full' });
            const parsed = parseEmail(detail.data);
            if (owner) cacheSet(`${owner}:${ids[i]}`, structuredClone(parsed));
            out[i] = parsed;
        }));
    }
    return out.filter(Boolean);
}

// Newest `maxResults` emails in the inbox. `owner` (the user's ID) turns on the cache.
async function fetchEmails(accessToken, maxResults = 20, owner = '') {
    const gmail   = getGmailClient(accessToken);
    const listRes = await gmail.users.messages.list({
        userId: 'me', maxResults, labelIds: ['INBOX']
    });
    const ids = (listRes.data.messages || []).map(m => m.id);
    return getDetails(gmail, ids, owner);
}

// Search the whole mailbox (not just the newest emails) with Gmail's own search
// syntax: plain words, from:, subject:, before:/after:, has:attachment …
// Sent mail, drafts and chats are left out; spam and trash are excluded by Gmail.
async function searchEmails(accessToken, query, maxResults = 50, owner = '') {
    const gmail   = getGmailClient(accessToken);
    const listRes = await gmail.users.messages.list({
        userId: 'me', maxResults, q: `${query} -in:sent -in:drafts -in:chats`
    });
    const ids = (listRes.data.messages || []).map(m => m.id);
    return getDetails(gmail, ids, owner);
}

function parseEmail(raw) {
    const headers = raw.payload.headers || [];
    const get = (name) =>
        (headers.find(h => h.name.toLowerCase() === name.toLowerCase()) || {}).value || '';

    // Walk every MIME part (emails are often multipart/mixed > multipart/alternative > text/plain)
    const decode = (data) => Buffer.from(String(data).replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf-8');
    let textBody = '', htmlBody = '';
    (function walk(part) {
        if (!part) return;
        const isAttachment = part.filename && part.filename.length > 0;
        if (!isAttachment && part.body?.data) {
            if (part.mimeType === 'text/plain' && !textBody) textBody = decode(part.body.data);
            else if (part.mimeType === 'text/html' && !htmlBody) htmlBody = decode(part.body.data);
        }
        (part.parts || []).forEach(walk);
    })(raw.payload);
    const { htmlToText, linksFromHtml } = require('./detection');
    const body = textBody || htmlToText(htmlBody);

    const links = [...new Set([
        ...[...body.matchAll(/https?:\/\/[^\s<>")\]]+/g)].map(m => m[0]),
        ...linksFromHtml(htmlBody)
    ])];

    const replyTo   = get('reply-to') || null;
    const messageId = get('message-id') || null;

    // ── Real SPF/DKIM/DMARC headers ──────────────────────────────
    const authResults    = get('authentication-results') || get('Authentication-Results') || '';
    const receivedSpf    = get('received-spf')           || get('Received-SPF')           || '';
    const arcAuthResults = get('arc-authentication-results') || '';

    // ── Attachment extraction ─────────────────────────────────────
    // Walk all MIME parts recursively to find attachments
    function extractAttachments(parts = []) {
        const found = [];
        for (const part of parts) {
            const disposition = (part.headers || []).find(
                h => h.name.toLowerCase() === 'content-disposition'
            )?.value || '';
            const isAttachment = disposition.toLowerCase().includes('attachment')
                              || (part.filename && part.filename.length > 0);
            if (isAttachment || part.filename) {
                const att = {
                    filename:  part.filename || 'unnamed',
                    mimeType:  part.mimeType || 'application/octet-stream',
                    size:      part.body?.size || 0,
                    attachmentId: part.body?.attachmentId || null
                };
                // small files come inline: keep the bytes for the attachment check, hidden from JSON
                if (part.body?.data) Object.defineProperty(att, '_content', { value: Buffer.from(part.body.data, 'base64url'), enumerable: false });
                found.push(att);
            }
            // Recurse into multipart children
            if (part.parts) found.push(...extractAttachments(part.parts));
        }
        return found;
    }
    const attachments = extractAttachments(raw.payload.parts || []);

    return {
        id:        raw.id,
        threadId:  raw.threadId,
        messageId,
        subject:   get('subject') || '(No Subject)',
        from:      get('from'),
        to:        get('to'),
        replyTo,
        date:      get('date'),
        snippet:   raw.snippet || '',
        body,
        links,
        labels:    raw.labelIds || [],
        attachments,       // ← array of { filename, mimeType, size, attachmentId }
        authResults,
        receivedSpf,
        arcAuthResults,
        html:            htmlBody,
        listUnsubscribe: get('list-unsubscribe') || null,
        listId:          get('list-id') || null,
        received:        headers.filter(h => h.name.toLowerCase() === 'received').map(h => h.value),
        xOriginatingIp:  get('x-originating-ip') || ''
    };
}

// threadOptions: { threadId, inReplyTo, references }
async function sendReply(accessToken, to, subject, body, threadOptions = {}) {
    const blocked = /no.?reply|noreply|postmaster|mailer.daemon|do.not.reply/i;
    if (!to || blocked.test(to)) {
        console.warn(`[Honeypot] Blocked reply to no-reply address: ${to}`);
        const err = new Error('NO_REPLY_ADDRESS');
        err.noReply = true;
        err.blockedAddress = to;
        throw err;
    }

    const gmail = getGmailClient(accessToken);

    // Build RFC 2822 headers — In-Reply-To and References make Gmail
    // show this as a reply in the same thread, not a new email
    const headers = [
        `To: ${to}`,
        `Subject: ${subject}`,
        'Content-Type: text/plain; charset=utf-8',
        'MIME-Version: 1.0'
    ];

    if (threadOptions.inReplyTo) {
        headers.push(`In-Reply-To: ${threadOptions.inReplyTo}`);
        headers.push(`References: ${threadOptions.references || threadOptions.inReplyTo}`);
    }

    const raw     = [...headers, '', body].join('\r\n');
    const encoded = Buffer.from(raw).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_');

    // Pass threadId so Gmail places the message in the existing thread
    const requestBody = { raw: encoded };
    if (threadOptions.threadId) requestBody.threadId = threadOptions.threadId;

    await gmail.users.messages.send({
        userId: 'me', requestBody
    });
}

// Move a specific email to Gmail spam by adding SPAM label + removing INBOX
async function moveToSpam(accessToken, gmailMsgId) {
    const gmail = getGmailClient(accessToken);
    await gmail.users.messages.modify({
        userId: 'me',
        id: gmailMsgId,
        requestBody: {
            addLabelIds:    ['SPAM'],
            removeLabelIds: ['INBOX']
        }
    });
}

// Create a Gmail filter so ALL future emails from this sender go to spam
async function createSpamFilter(accessToken, senderEmail) {
    // Extract plain email address from "Name <email>" format
    const match = senderEmail.match(/<([^>]+)>/) || senderEmail.match(/([^\s]+@[^\s]+)/);
    const email = match ? match[1] : senderEmail;
    if (!email || !email.includes('@')) return; // safety check

    const gmail = getGmailClient(accessToken);
    await gmail.users.settings.filters.create({
        userId: 'me',
        requestBody: {
            criteria: { from: email },
            action:   { addLabelIds: ['SPAM'], removeLabelIds: ['INBOX'] }
        }
    });
}

// Undo spam: remove SPAM label and restore INBOX
async function removeFromSpam(accessToken, gmailMsgId) {
    const gmail = getGmailClient(accessToken);
    await gmail.users.messages.modify({
        userId: 'me',
        id: gmailMsgId,
        requestBody: {
            addLabelIds:    ['INBOX'],
            removeLabelIds: ['SPAM']
        }
    });
}

// One attachment's bytes (for the attachment check)
async function getAttachment(accessToken, messageId, attachmentId) {
    const gmail = getGmailClient(accessToken);
    const { data } = await gmail.users.messages.attachments.get({ userId: 'me', messageId, id: attachmentId });
    return Buffer.from(data.data || '', 'base64url');
}

module.exports = { fetchEmails, searchEmails, sendReply, getGmailClient, moveToSpam, createSpamFilter, removeFromSpam, parseEmail, getAttachment };
