// ============================================================
// routes/settings.js — User settings (PostgreSQL async)
// ============================================================
const express         = require('express');
const { requireAuth } = require('../middleware/authMiddleware');
const { getSettings, updateSettings } = require('../database/db');
const { getSafeSenders, addSafeSender, removeSafeSender } = require('../database/db');

const router = express.Router();

const defaults = {
  realTimeAlerts: true, emailNotifications: false, soundAlerts: true,
  multiLayerScan: true, linkScanning: true,
  honeypotMode: false, notifyOnSuspicious: true, notifyOnDangerous: true
};

router.get('/settings', requireAuth, async (req, res) => {
  try {
    const raw = await getSettings(req.session.user.id);
    res.json({ success: true, settings: {
      realTimeAlerts:     !!raw.real_time_alerts,
      emailNotifications: !!raw.email_notifications,
      soundAlerts:        !!raw.sound_alerts,
      autoBlock:          !!raw.auto_block,
      multiLayerScan:     !!raw.multi_layer_scan,
      linkScanning:       !!raw.link_scanning,
      honeypotMode:       !!raw.honeypot_mode,
      telegramEnabled:    !!raw.telegram_enabled,
      scanFrequency:      raw.scan_frequency || 'realtime',
      weeklyDigest:       !!raw.weekly_digest,
      lastDigestAt:       raw.last_digest_at || null,
      discordConnected:   !!raw.discord_webhook,
      honeypotPersona:    raw.honeypot_persona || 'teacher'
    }});
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

router.put('/settings', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const map = {
      realTimeAlerts: 'real_time_alerts', emailNotifications: 'email_notifications',
      soundAlerts: 'sound_alerts',
      multiLayerScan: 'multi_layer_scan', linkScanning: 'link_scanning',
      honeypotMode: 'honeypot_mode', telegramEnabled: 'telegram_enabled',
      scanFrequency: 'scan_frequency', autoBlock: 'auto_block', weeklyDigest: 'weekly_digest', honeypotPersona: 'honeypot_persona'
    };
    const updates = {};
    if ('honeypotPersona' in (req.body || {}) && !require('../services/nami').PERSONAS[req.body.honeypotPersona])
      return res.status(400).json({ success: false, error: 'Unknown persona' });
    Object.entries(req.body).forEach(([k, v]) => {
      if (map[k]) updates[map[k]] = typeof v === 'boolean' ? (v ? 1 : 0) : v;
    });
    await updateSettings(userId, updates);
    try { await require('../database/db').logUserActivity(userId, 'Changed settings', Object.keys(req.body || {}).join(', ')); } catch (_) {}
    const raw = await getSettings(userId);
    res.json({ success: true, settings: {
      realTimeAlerts:     !!raw.real_time_alerts,
      emailNotifications: !!raw.email_notifications,
      soundAlerts:        !!raw.sound_alerts,
      autoBlock:          !!raw.auto_block,
      multiLayerScan:     !!raw.multi_layer_scan,
      linkScanning:       !!raw.link_scanning,
      honeypotMode:       !!raw.honeypot_mode,
      telegramEnabled:    !!raw.telegram_enabled,
      scanFrequency:      raw.scan_frequency || 'realtime',
      weeklyDigest:       !!raw.weekly_digest,
      lastDigestAt:       raw.last_digest_at || null,
      discordConnected:   !!raw.discord_webhook,
      honeypotPersona:    raw.honeypot_persona || 'teacher'
    }});
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

router.post('/settings/reset', requireAuth, async (req, res) => {
  try {
    await updateSettings(req.session.user.id, {
      real_time_alerts: 1, email_notifications: 0, sound_alerts: 1,
      multi_layer_scan: 1, link_scanning: 1, honeypot_mode: 0
    });
    res.json({ success: true, settings: defaults });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── Trusted senders ───────────────────────────────────────────
router.get('/settings/safe-senders', requireAuth, async (req, res) => {
  try { res.json({ success: true, senders: await getSafeSenders(req.session.user.id) }); }
  catch (err) { res.status(500).json({ success: false, error: err.message }); }
});
router.post('/settings/safe-senders', requireAuth, async (req, res) => {
  try {
    const added = await addSafeSender(req.session.user.id, (req.body || {}).sender);
    if (!added) return res.status(400).json({ success: false, error: 'Enter a valid email address.' });
    res.json({ success: true, sender: added });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});
router.delete('/settings/safe-senders/:sender', requireAuth, async (req, res) => {
  try { res.json({ success: true, removed: await removeSafeSender(req.session.user.id, req.params.sender) }); }
  catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

module.exports = router;
