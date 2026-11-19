// services/teamAlerts.js — alerts for the Genjutsu team (admins), not for users.
// Channels, each used only when set up:
//   • Discord  — webhook saved (encrypted) in Admin → Settings → Team alerts
//   • Email    — SMTP_URL in the server settings (e.g. smtps://you%40gmail.com:APP_PASSWORD@smtp.gmail.com:465);
//                sent to TEAM_ALERT_EMAIL, or to ADMIN_EMAIL
//   • Telegram — only if TELEGRAM_BOT_TOKEN is set (blocked in Nepal since July 2025, so off by default)
// What is sent:
//   • security: new-device admin logins, approvals, read-only changes  — always (when a channel exists)
//   • threats:  DANGEROUS emails found for real users (no demo), only when "Team threat alerts" is on,
//               at most 20 an hour so a big campaign doesn't flood the channel
//   • honeypot: a scammer was engaged — only when "Team threat alerts" is on
const db = () => require('../database/db');
const { isDiscordWebhook, sealWebhook, openWebhook } = require('./alerts');

const HOURLY_THREAT_CAP = 20;
let sentThisHour = { hour: -1, n: 0 };

async function getSetting(key) { try { return await db().getSystemSetting(key); } catch (_) { return null; } }
async function discordUrl() {
  const sealed = await getSetting('team_discord_webhook');
  if (!sealed) return null;
  try { return openWebhook(sealed); } catch (_) { return null; }
}
const threatAlertsOn = async () => (await getSetting('team_alerts')) !== 'false';

let mailer = null;
function emailTransport() {
  if (!process.env.SMTP_URL) return null;
  if (!mailer) mailer = require('nodemailer').createTransport(process.env.SMTP_URL);
  return mailer;
}
const emailTo = () => process.env.TEAM_ALERT_EMAIL || process.env.ADMIN_EMAIL || null;

async function deliver({ title, lines = [], color = 0x7CF2B8 }) {
  const out = { discord: false, email: false, telegram: false };
  const url = await discordUrl();
  if (url) {
    try {
      const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, signal: AbortSignal.timeout(8000),
        body: JSON.stringify({ username: 'Genjutsu team', embeds: [{ title: title.slice(0, 250), color,
          description: lines.map(l => String(l).slice(0, 300)).join('\n').slice(0, 3800), timestamp: new Date().toISOString(),
          footer: { text: 'Genjutsu admin · open the portal to act' } }] }) });
      out.discord = res.ok;
    } catch (e) { console.warn('⚠️  Team Discord alert failed:', e.message); }
  }
  const t = emailTransport(), to = emailTo();
  if (t && to) {
    try {
      await t.sendMail({ from: process.env.SMTP_FROM || to, to, subject: `[Genjutsu] ${title}`, text: [...lines, '', 'Open the admin portal to act.'].join('\n') });
      out.email = true;
    } catch (e) { console.warn('⚠️  Team email alert failed:', e.message); }
  }
  if (process.env.TELEGRAM_BOT_TOKEN) {
    try { await require('./telegramService').sendAdminAlert(`${title}\n${lines.join('\n')}`); out.telegram = true; } catch (_) {}
  }
  return out;
}

const fire = (p) => { p.catch(e => console.warn('⚠️  Team alert:', e.message)); };

// Security events always go out
function security(text) { fire(deliver({ title: '🛡️ Admin security', lines: [text], color: 0xFFC266 })); }

function threat({ userId, level, subject, from, score, reasons }) {
  if (level !== 'dangerous' || String(userId || '').startsWith('demo-')) return;
  fire((async () => {
    if (!(await threatAlertsOn())) return;
    const hour = Math.floor(Date.now() / 36e5);
    if (sentThisHour.hour !== hour) sentThisHour = { hour, n: 0 };
    if (++sentThisHour.n > HOURLY_THREAT_CAP) return;
    await deliver({ title: '🚨 Dangerous email caught', color: 0xFF5A5F,
      lines: [`Subject: ${subject || '(no subject)'}`, `From: ${from || '—'}`, `Score: ${score}/100`, `Why: ${(reasons || [])[0] || '—'}`] });
  })());
}

function honeypot({ userId, senderEmail, subject }) {
  if (String(userId || '').startsWith('demo-')) return;
  fire((async () => {
    if (!(await threatAlertsOn())) return;
    await deliver({ title: '🍯 Nami engaged a scammer', lines: [`Scammer: ${senderEmail}`, `Subject: ${subject || '—'}`] });
  })());
}

async function status() {
  return {
    discord: !!(await discordUrl()),
    email: !!(process.env.SMTP_URL && emailTo()),
    telegram: process.env.TELEGRAM_BOT_TOKEN ? require('./telegramService').status() : 'off',
    threatAlerts: await threatAlertsOn(),
  };
}
async function setDiscord(url, by) {
  if (url && !isDiscordWebhook(url)) throw new Error('That is not a Discord webhook link.');
  await db().updateSystemSetting('team_discord_webhook', url ? sealWebhook(url) : '', by);
}
const test = () => deliver({ title: '✅ Team alerts are connected', lines: ['You will get admin security alerts and dangerous-email alerts here.'] });

module.exports = { security, threat, honeypot, status, setDiscord, test, deliver, HOURLY_THREAT_CAP };
