// ============================================================
// services/alerts.js — Discord alerts for new threats
// The webhook URL is per user and stored encrypted.
// ============================================================
const { seal, open } = require('./mail/secretBox');

const DISCORD = /^https:\/\/(?:ptb\.|canary\.)?(?:discord|discordapp)\.com\/api\/webhooks\/\d+\/[\w-]+$/;
const isDiscordWebhook = (url) => DISCORD.test(String(url || '').trim());

async function postDiscord(url, threat, { test = false } = {}) {
  if (!isDiscordWebhook(url)) throw new Error('Not a Discord webhook URL');
  const color = threat.level === 'dangerous' ? 0xFF5A5F : 0xFFB547;
  const body = test
    ? { username: 'Genjutsu', content: '✅ Genjutsu alerts are connected. You will get a message here when a dangerous or suspicious email arrives.' }
    : { username: 'Genjutsu', embeds: [{
        title: `${threat.level === 'dangerous' ? '🚨 Dangerous' : '⚠️ Suspicious'} email detected`,
        color,
        fields: [
          { name: 'Subject', value: String(threat.subject || '(no subject)').slice(0, 250) },
          { name: 'From', value: String(threat.from || '').slice(0, 250) || '—' },
          { name: 'Score', value: `${threat.score}/100`, inline: true },
          { name: 'Why', value: String((threat.reasons || [])[0] || '—').slice(0, 250), inline: true }
        ],
        footer: { text: 'Genjutsu · open the app to investigate' },
        timestamp: new Date().toISOString()
      }] };
  const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(8000) });
  if (!res.ok) throw new Error(`Discord answered ${res.status}`);
}

// Fire-and-forget for a scan's new threats
function alertThreats(sealedUrl, threats) {
  if (!sealedUrl || !threats.length) return;
  let url;
  try { url = open(sealedUrl); } catch (_) { return; }
  (async () => {
    for (const t of threats.slice(0, 5)) {
      try { await postDiscord(url, t); } catch (err) { console.warn('⚠️  Discord alert failed:', err.message); return; }
    }
  })();
}

module.exports = { isDiscordWebhook, postDiscord, alertThreats, sealWebhook: (u) => seal(String(u).trim()), openWebhook: (s) => open(s) };
