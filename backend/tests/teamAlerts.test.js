// Team alerts: Discord/email instead of Telegram, only what matters, never flooding
const { test } = require('node:test');
const assert = require('node:assert');
const { req } = require('./_setup');
const db = req('database/db');
const { sealWebhook } = req('services/alerts');
const team = req('services/teamAlerts');

const settings = { team_discord_webhook: sealWebhook('https://discord.com/api/webhooks/1/abc'), team_alerts: 'true' };
db.getSystemSetting = async (k) => settings[k] ?? null;
db.updateSystemSetting = async (k, v) => { settings[k] = v; };
let posts = [];
global.fetch = async (url, opts) => { posts.push({ url, body: JSON.parse(opts.body) }); return { ok: true }; };
const flush = () => new Promise(r => setTimeout(r, 30));

test('only dangerous emails of real users are sent, at most 20 an hour', async () => {
  posts = [];
  team.threat({ userId: 'u1', level: 'suspicious', subject: 'a' });
  team.threat({ userId: 'demo-x', level: 'dangerous', subject: 'b' });
  await flush(); assert.equal(posts.length, 0);
  for (let i = 0; i < 25; i++) team.threat({ userId: 'u1', level: 'dangerous', subject: 'x' + i, score: 90, reasons: ['Look-alike'] });
  await flush(); assert.equal(posts.length, 20);
  assert.match(posts[0].body.embeds[0].title, /Dangerous email/);
});
test('the on/off switch is respected; security alerts always go out', async () => {
  posts = []; settings.team_alerts = 'false';
  team.honeypot({ userId: 'u2', senderEmail: 's@x', subject: 'y' });
  team.security('boss@x.com signed in from a new device');
  await flush();
  assert.equal(posts.length, 1); assert.match(posts[0].body.embeds[0].description, /new device/);
  settings.team_alerts = 'true';
});
test('only real Discord webhook links are accepted, stored encrypted', async () => {
  await assert.rejects(team.setDiscord('https://evil.example/hook', 'a'));
  await team.setDiscord('https://discord.com/api/webhooks/2/zz', 'a');
  assert.ok(!settings.team_discord_webhook.includes('discord.com'));
  assert.equal((await team.status()).discord, true);
});
