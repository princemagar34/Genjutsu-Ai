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

    return {
        id:       raw.id,
        threadId: raw.threadId,
        subject:  get('subject') || '(No Subject)',
        from:     get('from'),
        to:       get('to'),
        date:     get('date'),
        snippet:  raw.snippet || '',
        body,
        links,
        labels:   raw.labelIds || []
    };
}

async function sendReply(accessToken, to, subject, body) {
    const gmail = getGmailClient(accessToken);
    const raw   = [`To: ${to}`, `Subject: ${subject}`,
                   'Content-Type: text/plain; charset=utf-8', '', body].join('\n');
    const encoded = Buffer.from(raw).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_');

    await gmail.users.messages.send({
        userId: 'me', requestBody: { raw: encoded }
    });
}

module.exports = { fetchEmails, sendReply, getGmailClient };
