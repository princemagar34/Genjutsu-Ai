# Genjutsu-Ai

AI-powered phishing detection and honeypot system — now for **Gmail, Outlook and any IMAP mailbox**.

## Supported mailboxes

| Sign-in option | Mailboxes | How it connects | Blocking a sender |
|---|---|---|---|
| Continue with Google | Gmail, Google Workspace | Gmail API (OAuth 2.0) | Gmail filter |
| Continue with Microsoft | Outlook.com, Hotmail, Live, Microsoft 365 | Microsoft Graph (OAuth 2.0) | Outlook inbox rule |
| Other email | Yahoo, iCloud, AOL, Zoho, GMX, Yandex, custom domains | IMAP + SMTP with an app password | Enforced by Genjutsu on every scan |

All three go through `backend/services/mail/` — one interface (`fetchEmails`, `sendReply`, `moveToSpam`,
`removeFromSpam`, `createSpamFilter`, `findLatestFrom`) with a provider per mailbox type. The nine-layer
threat engine, honeypot (Nami), reports and admin portal work the same for every provider.

### Security notes
- IMAP app passwords are sealed with AES-256-GCM (`MAIL_ENCRYPTION_KEY`) — never stored in plain text.
- Custom IMAP/SMTP servers must resolve to public addresses on mail ports (SSRF protection).
- One Genjutsu account per email address; a second provider cannot take over an existing account.
- IMAP sign-in is rate-limited (5 attempts / 15 min / IP); Microsoft sign-in uses an OAuth `state` check.

## Setup
1. `cd backend && npm install` (Node 22+)
2. Copy `backend/.env.example` to `backend/.env` and fill in the values.
3. Microsoft sign-in: register an app at portal.azure.com (steps in `.env.example`).
4. `npm start`
