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
    auth.setCredentials({ access_token: accessToken });
    return google.gmail({ version: 'v1', auth });
}

async function fetchEmails(accessToken, maxResults = 20) {
    const gmail   = getGmailClient(accessToken);
    const listRes = await gmail.users.messages.list({
        userId: 'me', maxResults, labelIds: ['INBOX']
    });

    const messages = listRes.data.messages || [];
    return Promise.all(messages.map(async (msg) => {
        const detail = await gmail.users.messages.get({
            userId: 'me', id: msg.id, format: 'full'
        });
        return parseEmail(detail.data);
    }));
}

function parseEmail(raw) {
    const headers = raw.payload.headers || [];
    const get = (name) =>
        (headers.find(h => h.name.toLowerCase() === name.toLowerCase()) || {}).value || '';

    let body = '';
    const parts = raw.payload.parts || [];
    const textPart = parts.find(p => p.mimeType === 'text/plain');
    if (textPart?.body?.data) {
        body = Buffer.from(textPart.body.data, 'base64').toString('utf-8');
    }

    const links = [...body.matchAll(/https?:\/\/[^\s]+/g)].map(m => m[0]);

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
                found.push({
                    filename:  part.filename || 'unnamed',
                    mimeType:  part.mimeType || 'application/octet-stream',
                    size:      part.body?.size || 0,
                    attachmentId: part.body?.attachmentId || null
                });
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
        arcAuthResults
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

module.exports = { fetchEmails, sendReply, getGmailClient };
