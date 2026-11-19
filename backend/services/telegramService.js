// ============================================================
// services/telegramService.js — Automatic Telegram Alerts
// Fires automatically — no manual trigger needed
// ============================================================
const axios = require('axios');

// Telegram is blocked by internet providers in Nepal (since July 2025), and a wrong
// bot token returns "Not Found". Either way, don't keep trying for every email:
// pause alerts for a while after a failure and only log it once.
const PAUSE_MS = 30 * 60 * 1000;
let pausedUntil = 0;
let disabledReason = null;

async function send(text) {
  if (!process.env.TELEGRAM_BOT_TOKEN || !process.env.TELEGRAM_CHAT_ID) return;
  if (disabledReason || Date.now() < pausedUntil) return;
  try {
    await axios.post(
      `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`,
      { chat_id: process.env.TELEGRAM_CHAT_ID, text, parse_mode: 'HTML' },
      { timeout: 8000 }
    );
  } catch (err) {
    const status = err.response?.status;
    if (status === 401 || status === 404) {
      disabledReason = 'bot token is wrong or the bot was deleted';
      console.warn(`⚠️  Telegram alerts turned off: ${disabledReason} (check TELEGRAM_BOT_TOKEN, then restart).`);
    } else {
      pausedUntil = Date.now() + PAUSE_MS;
      console.warn(`⚠️  Telegram unreachable (${err.response?.data?.description || err.code || err.message}). Pausing alerts for 30 min.`);
    }
  }
}

function esc(str) {
  return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function status() {
  if (!process.env.TELEGRAM_BOT_TOKEN || !process.env.TELEGRAM_CHAT_ID) return 'off';
  if (disabledReason) return 'broken';
  if (Date.now() < pausedUntil) return 'paused';
  return 'on';
}

// For admin alerts (e.g. a login from a new device). Fire and forget.
const sendAdminAlert = (text) => send(`🛡️ <b>Genjutsu admin</b>\n\n${esc(text)}`);

module.exports = { sendAdminAlert, status };
