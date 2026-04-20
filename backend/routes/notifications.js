// routes/notifications.js — async PostgreSQL version
const express         = require('express');
const { requireAuth } = require('../middleware/authMiddleware');
const {
  getAlerts, markAllAlertsRead,
  getUnreadRemarks, markRemarksRead
} = require('../database/db');

const router = express.Router();

// ── GET /api/notifications — threat email alerts ──────────────
router.get('/notifications', requireAuth, async (req, res) => {
  try {
    const alerts = await getAlerts(req.session.user.id, 20);
    res.json({ success: true, count: alerts.length, alerts });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── PUT /api/notifications/read — mark all email alerts read ──
router.put('/notifications/read', requireAuth, async (req, res) => {
  try {
    await markAllAlertsRead(req.session.user.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── GET /api/notifications/remarks — unread admin remarks ─────
router.get('/notifications/remarks', requireAuth, async (req, res) => {
  try {
    const remarks = await getUnreadRemarks(req.session.user.id);
    res.json({ success: true, count: remarks.length, remarks });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── PUT /api/notifications/remarks/read — mark remarks seen ───
router.put('/notifications/remarks/read', requireAuth, async (req, res) => {
  try {
    await markRemarksRead(req.session.user.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
