// ============================================================
// routes/settings.js — User settings (PostgreSQL async)
// ============================================================
const express         = require('express');
const { requireAuth } = require('../middleware/authMiddleware');
const { getSettings, updateSettings } = require('../database/db');

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
      scanFrequency:      raw.scan_frequency || 'realtime'
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
      scanFrequency: 'scan_frequency'
    };
    const updates = {};
    Object.entries(req.body).forEach(([k, v]) => {
      if (map[k]) updates[map[k]] = typeof v === 'boolean' ? (v ? 1 : 0) : v;
    });
    await updateSettings(userId, updates);
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
      scanFrequency:      raw.scan_frequency || 'realtime'
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

module.exports = router;
