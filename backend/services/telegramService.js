// ============================================================
// services/telegramService.js — Automatic Telegram Alerts
// Fires automatically — no manual trigger needed
// ============================================================
const axios = require('axios');

async function send(text) {
  if (!process.env.TELEGRAM_BOT_TOKEN || !process.env.TELEGRAM_CHAT_ID) return;
  try {
    await axios.post(
      `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`,
      { chat_id: process.env.TELEGRAM_CHAT_ID, text, parse_mode: 'HTML' }
    );
  } catch (err) {
    console.warn('⚠️  Telegram failed:', err.response?.data?.description || err.message);
  }
}

async function sendThreatAlert({ level, subject, from, score, reasons }) {
  const emoji     = level === 'dangerous' ? '🚨' : '⚠️';
  const topReason = reasons && reasons.length > 0 ? reasons[0] : 'Threat detected';
  await send(
    `${emoji} <b>Genjutsu — ${level.toUpperCase()} EMAIL</b>\n\n` +
    `📧 <b>Subject:</b> ${esc(subject)}\n` +
    `👤 <b>From:</b> ${esc(from)}\n` +
    `🎯 <b>Threat Score:</b> ${score}/100\n` +
    `🔍 <b>Reason:</b> ${esc(topReason)}\n\n` +
    `🛡️ <i>Genjutsu has flagged this email.</i>`
  );
}

async function sendHoneypotAlert({ senderEmail, subject }) {
  await send(
    `🍯 <b>Genjutsu — Honeypot Activated</b>\n\n` +
    `🤖 Auto-reply sent to scammer\n` +
    `📧 <b>To:</b> ${esc(senderEmail)}\n` +
    `📝 <b>Subject:</b> ${esc(subject)}\n\n` +
    `⏱️ <i>Wasting their time so they cannot waste yours!</i>`
  );
}

function esc(str) {
  return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

module.exports = { sendThreatAlert, sendHoneypotAlert };
