// ============================================================
// routes/notifications.js — Real notification bell data
// GET  /api/notifications        → unread alerts for this user
// PUT  /api/notifications/read   → mark all as read
// ============================================================
const express         = require('express');
const { requireAuth } = require('../middleware/authMiddleware');
const { getAlerts, markAllAlertsRead } = require('../database/db');

const router = express.Router();

// GET /api/notifications
router.get('/notifications', requireAuth, (req, res) => {
  try {
    const alerts = getAlerts(req.session.user.id, 20);
    res.json({ success: true, count: alerts.length, alerts });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// PUT /api/notifications/read — mark all read
router.put('/notifications/read', requireAuth, (req, res) => {
  try {
    markAllAlertsRead(req.session.user.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
