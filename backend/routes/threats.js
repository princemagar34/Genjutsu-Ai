// ============================================================
// routes/threats.js — Threats + PDF report on button click
// ============================================================
const express                = require('express');
const { requireAuth }        = require('../middleware/authMiddleware');
const { fetchEmails }        = require('../services/gmailService');
const { scanEmails }         = require('../services/threatService');
const { generateUserReport } = require('../services/reportService');
const { getReportData }      = require('../database/db');

const router = express.Router();

// GET /api/threats — all threats list
router.get('/threats', requireAuth, async (req, res) => {
  try {
    const emails  = await fetchEmails(req.session.user.accessToken, 100);
    // FIX: scan each email individually so one bad/malformed email
    // doesn't crash the entire threats response
    const scanned = emails.map(email => {
      try { return { ...email, threat: require('../services/threatService').analyseEmail(email) }; }
      catch(e) { return { ...email, threat: { level:'safe', score:0, reasons:['Parse error'], mlResult:{}, nlpFeatures:{} } }; }
    });
    const threats = scanned
      .filter(e => e.threat.level !== 'safe')
      .sort((a, b) => b.threat.score - a.threat.score);

    res.json({
      success: true,
      summary: {
        total:      threats.length,
        dangerous:  threats.filter(e => e.threat.level === 'dangerous').length,
        suspicious: threats.filter(e => e.threat.level === 'suspicious').length
      },
      threats
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/threats/summary — quick stats
router.get('/threats/summary', requireAuth, async (req, res) => {
  try {
    const emails  = await fetchEmails(req.session.user.accessToken, 100);
    const scanned = scanEmails(emails);
    res.json({
      success:    true,
      total:      scanned.length,
      safe:       scanned.filter(e => e.threat.level === 'safe').length,
      suspicious: scanned.filter(e => e.threat.level === 'suspicious').length,
      dangerous:  scanned.filter(e => e.threat.level === 'dangerous').length
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── PDF REPORT — called when user clicks "Generate Report" ────
// GET /api/threats/report
// Downloads a PDF scoped to the logged-in user's Gmail account
router.get('/threats/report', requireAuth, (req, res) => {
  try {
    const user       = req.session.user;           // { name, email, id, ... }
    const reportData = getReportData(user.id);     // pulls from SQLite
    generateUserReport(res, user, reportData);     // streams PDF to browser
  } catch (err) {
    console.error('PDF report error:', err.message);
    res.status(500).json({ success: false, error: 'Could not generate report: ' + err.message });
  }
});

module.exports = router;
