// ============================================================
// routes/account.js — rules, activity, phishing reports, weekly
// digest, Discord alerts and account deletion (all per user)
// ============================================================
const express = require('express');
const { requireAuth } = require('../middleware/authMiddleware');
const { rateLimit }   = require('../middleware/rateLimit');
const db     = require('../database/db');
const mail   = require('../services/mail');
const rules  = require('../services/rules');
const alerts = require('../services/alerts');
const { sendDigest } = require('../services/digest');
const { withTokens } = require('../services/mail/tokens');

const router = express.Router();
const uid = (req) => req.session.user.id;

// ── Rules ─────────────────────────────────────────────────────
router.get('/account/rules', requireAuth, async (req, res) => {
  try { res.json({ success: true, rules: (await db.getRules(uid(req))).map(r => ({ ...r, description: rules.describe(r) })) }); }
  catch (err) { res.status(500).json({ success: false, error: err.message }); }
});
router.post('/account/rules', requireAuth, async (req, res) => {
  const rule = { field: req.body?.field, value: String(req.body?.value || '').trim().toLowerCase(), action: req.body?.action };
  const problem = rules.validateRule(rule);
  if (problem) return res.status(400).json({ success: false, error: problem });
  if ((await db.getRules(uid(req))).length >= 100) return res.status(400).json({ success: false, error: 'You can have up to 100 rules.' });
  try {
    const id = await db.addRule(uid(req), rule);
    await db.logUserActivity(uid(req), 'Added rule', `${rules.describe(rule)} → ${rule.action}`);
    res.json({ success: true, id });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});
router.delete('/account/rules/:id', requireAuth, async (req, res) => {
  try { await db.deleteRule(uid(req), req.params.id); await db.logUserActivity(uid(req), 'Removed rule', ''); res.json({ success: true }); }
  catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── Activity ──────────────────────────────────────────────────
router.get('/account/activity', requireAuth, async (req, res) => {
  try { res.json({ success: true, activity: await db.getUserActivity(uid(req), 50) }); }
  catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── Report phishing to the Anti-Phishing Working Group ───────
const APWG = 'reportphishing@apwg.org';
router.post('/account/report-phishing/:id', requireAuth,
  rateLimit({ name: 'report', windowMs: 60 * 60 * 1000, max: 10, message: 'You can report up to 10 emails an hour.' }),
  async (req, res) => {
    const note = 'This phishing email was reported by a Genjutsu user. The original message is attached unchanged.';
    try {
      if (req.session.user.provider === 'demo') return res.json({ success: true, message: 'Demo: nothing was actually sent.' });
      await mail.forwardAsAttachment(req.session.user, req.params.id, APWG, note);
      await db.logUserActivity(uid(req), 'Reported phishing to APWG', String(req.body?.subject || '').slice(0, 200));
      res.json({ success: true, message: `Sent to ${APWG}` });
    } catch (err) {
      console.error('[Report] failed:', err.message);
      res.status(500).json({ success: false, error: 'Could not send the report. ' + err.message });
    }
  });

// ── Weekly digest: send one now ───────────────────────────────
router.post('/account/digest/send', requireAuth,
  rateLimit({ name: 'digest', windowMs: 60 * 60 * 1000, max: 3, message: 'You can send up to 3 digests an hour.' }),
  async (req, res) => {
    try {
      const out = await sendDigest(uid(req), req.session.user);
      res.json({ success: true, subject: req.session.user.provider === 'demo' ? `${out.subject} (demo: not actually emailed)` : out.subject });
    } catch (err) { res.status(500).json({ success: false, error: err.message }); }
  });

// ── Discord alerts ────────────────────────────────────────────
router.put('/account/discord', requireAuth, async (req, res) => {
  const url = String(req.body?.url || '').trim();
  if (url && !alerts.isDiscordWebhook(url)) return res.status(400).json({ success: false, error: 'Paste a Discord webhook URL (Server settings → Integrations → Webhooks → Copy URL).' });
  try {
    await db.setDiscordWebhook(uid(req), url ? alerts.sealWebhook(url) : null);
    await db.logUserActivity(uid(req), url ? 'Connected Discord alerts' : 'Disconnected Discord alerts', '');
    res.json({ success: true, connected: !!url });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});
router.post('/account/discord/test', requireAuth,
  rateLimit({ name: 'discordtest', windowMs: 10 * 60 * 1000, max: 5 }),
  async (req, res) => {
    try {
      const raw = (await db.getSettings(uid(req))).discord_webhook;
      if (!raw) return res.status(400).json({ success: false, error: 'Connect a Discord webhook first.' });
      await alerts.postDiscord(alerts.openWebhook(raw), {}, { test: true });
      res.json({ success: true });
    } catch (err) { res.status(500).json({ success: false, error: err.message }); }
  });

// ── Delete account ────────────────────────────────────────────
router.delete('/account', requireAuth,
  rateLimit({ name: 'delete', windowMs: 60 * 60 * 1000, max: 3 }),
  async (req, res) => {
    if (req.body?.confirm !== 'DELETE') return res.status(400).json({ success: false, error: 'Type DELETE to confirm.' });
    const user = req.session.user;
    try {
      // Revoke Google access too, so Genjutsu can no longer read the mailbox
      if (user.provider === 'google' || !user.provider) {
        const t = withTokens(user);
        const token = t.refreshToken || t.accessToken;
        if (token) {
          try { await fetch(`https://oauth2.googleapis.com/revoke?token=${encodeURIComponent(token)}`, { method: 'POST', signal: AbortSignal.timeout(6000) }); }
          catch (_) { /* revoking is best effort; data is deleted either way */ }
        }
      }
      await db.deleteUserData(user.id);
      req.session.destroy(() => res.json({ success: true }));
    } catch (err) {
      console.error('[Delete account] failed:', err.message);
      res.status(500).json({ success: false, error: 'Could not delete everything. Please try again or email us.' });
    }
  });

// ── SIEM export (download) ───────────────────────────────────
router.get('/account/export/siem', requireAuth, async (req, res) => {
  try {
    const siem = require('../services/siem');
    const days = Math.min(Math.max(parseInt(req.query.days) || 30, 1), 365);
    const { threats, activity } = await db.getSiemRows(uid(req), days);
    const out = siem.render(siem.toEvents(req.session.user, threats, activity), String(req.query.format || 'jsonl'));
    res.setHeader('Content-Disposition', `attachment; filename="genjutsu-events-${new Date().toISOString().slice(0, 10)}.${out.ext}"`);
    res.type(out.type).send(out.body);
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── API keys ─────────────────────────────────────────────────
router.get('/account/api-keys', requireAuth, async (req, res) => {
  try { res.json({ success: true, keys: await db.listApiKeys(uid(req)) }); }
  catch (err) { res.status(500).json({ success: false, error: err.message }); }
});
router.post('/account/api-keys', requireAuth, rateLimit({ name: 'keys', windowMs: 60 * 60 * 1000, max: 10 }), async (req, res) => {
  if (req.session.user.provider === 'demo') return res.status(403).json({ success: false, error: 'API keys are not available in the demo.' });
  try {
    if ((await db.listApiKeys(uid(req))).length >= 5) return res.status(400).json({ success: false, error: 'You can have up to 5 keys. Revoke one first.' });
    const { id, key } = await db.createApiKey(uid(req), req.body?.name);
    await db.logUserActivity(uid(req), 'Created API key', String(req.body?.name || ''));
    res.json({ success: true, id, key });   // shown once; only a hash is stored
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});
router.delete('/account/api-keys/:id', requireAuth, async (req, res) => {
  try { await db.revokeApiKey(uid(req), req.params.id); await db.logUserActivity(uid(req), 'Revoked API key', ''); res.json({ success: true }); }
  catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── Your organization (organization) ──────────────────────────────
// Admins of your organization can see your scan results and threats in the admin portal.
router.get('/account/org', requireAuth, async (req, res) => {
  try { res.json({ success: true, org: await require('../services/orgs').forUser(uid(req)) }); }
  catch (err) { res.status(500).json({ success: false, error: err.message }); }
});
router.post('/account/org/join', requireAuth, rateLimit({ name: 'orgjoin', windowMs: 15 * 60 * 1000, max: 10, message: 'Too many tries. Wait a few minutes.' }), async (req, res) => {
  try {
    const r = await require('../services/orgs').joinByInvite(req.session.user, String(req.body?.code || '').slice(0, 64));
    db.logUserActivity(uid(req), 'Joined organization', r.name);
    res.json({ success: true, ...r });
  } catch (err) { res.status(400).json({ success: false, error: err.message }); }
});
router.post('/account/org/leave', requireAuth, async (req, res) => {
  try {
    const orgs = require('../services/orgs');
    const mine = await orgs.forUser(uid(req));
    if (!mine) return res.json({ success: true });
    await orgs.removeMember(mine.org_id, uid(req));
    db.logUserActivity(uid(req), 'Left organization', mine.name);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── Announcements from the Genjutsu team (shown as a banner) ─
router.get('/announcements', requireAuth, async (req, res) => {
  try { res.json({ success: true, announcements: await require('../database/adminDb').activeAnnouncements(req.session.user?.id) }); }
  catch (_) { res.json({ success: true, announcements: [] }); }
});

module.exports = router;
