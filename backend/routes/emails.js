// ============================================================
// routes/emails.js — Fetch, scan, save to DB, alert Telegram
// ============================================================
const express                      = require('express');
const { requireAuth }              = require('../middleware/authMiddleware');
const { fetchEmails }              = require('../services/gmailService');
const { scanEmails, analyseEmail } = require('../services/threatService');
const { sendThreatAlert }          = require('../services/telegramService');
const { saveEmailScan }            = require('../database/db');

const router    = express.Router();
const alertedIds = new Set(); // prevent duplicate Telegram alerts per server session

router.get('/emails', requireAuth, async (req, res) => {
  try {
    const limit  = Math.min(parseInt(req.query.limit) || 50, 100);
    const filter = req.query.filter || 'all';
    const userId = req.session.user.id;

    const emails  = await fetchEmails(req.session.user.accessToken, limit);
    // FIX: scan per-email so one null From/malformed email never crashes the whole list
    const scanned = emails.map(email => {
      try { return { ...email, threat: analyseEmail(email) }; }
      catch(e) { return { ...email, threat: { level:'safe', score:0, reasons:[], mlResult:{}, nlpFeatures:{} } }; }
    });

    // Save to DB + fire Telegram for new threats
    for (const email of scanned) {
      saveEmailScan(email, email.threat, userId);
      if (email.threat.level !== 'safe' && !alertedIds.has(email.id)) {
        alertedIds.add(email.id);
        sendThreatAlert({
          level: email.threat.level, subject: email.subject,
          from: email.from, score: email.threat.score, reasons: email.threat.reasons
        });
      }
    }

    const filtered = filter === 'all' ? scanned : scanned.filter(e => e.threat.level === filter);
    res.json({ success: true, total: filtered.length, emails: filtered });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

router.get('/emails/:id', requireAuth, async (req, res) => {
  try {
    const emails = await fetchEmails(req.session.user.accessToken, 100);
    const email  = emails.find(e => e.id === req.params.id);
    if (!email) return res.status(404).json({ success: false, error: 'Email not found' });
    res.json({ success: true, email: { ...email, threat: analyseEmail(email) } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
