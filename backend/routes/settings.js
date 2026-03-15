// ============================================================
// routes/settings.js — User settings (saved to SQLite)
// ============================================================
const express         = require('express');
const { requireAuth } = require('../middleware/authMiddleware');
const { getSettings, updateSettings } = require('../database/db');

const router = express.Router();

const defaults = {
  realTimeAlerts: true, emailNotifications: false, soundAlerts: true,
  autoBlock: true, multiLayerScan: true, linkScanning: true,
  honeypotMode: false, notifyOnSuspicious: true, notifyOnDangerous: true
};

router.get('/settings', requireAuth, (req, res) => {
  const raw = getSettings(req.session.user.id);
  // Convert SQLite integers to booleans for frontend
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
});

router.put('/settings', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  // Map camelCase keys to snake_case DB columns
  const map = {
    realTimeAlerts: 'real_time_alerts', emailNotifications: 'email_notifications',
    soundAlerts: 'sound_alerts', autoBlock: 'auto_block',
    multiLayerScan: 'multi_layer_scan', linkScanning: 'link_scanning',
    honeypotMode: 'honeypot_mode', telegramEnabled: 'telegram_enabled',
    scanFrequency: 'scan_frequency'
  };
  const updates = {};
  Object.entries(req.body).forEach(([k, v]) => {
    if (map[k]) updates[map[k]] = typeof v === 'boolean' ? (v ? 1 : 0) : v;
  });
  updateSettings(userId, updates);
  const raw = getSettings(userId);
  res.json({ success: true, settings: raw });
});

router.post('/settings/reset', requireAuth, (req, res) => {
  updateSettings(req.session.user.id, {
    real_time_alerts: 1, email_notifications: 0, sound_alerts: 1,
    auto_block: 1, multi_layer_scan: 1, link_scanning: 1, honeypot_mode: 0
  });
  res.json({ success: true, settings: defaults });
});

module.exports = router;
