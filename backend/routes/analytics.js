// routes/analytics.js — async PostgreSQL version
const express         = require('express');
const { requireAuth } = require('../middleware/authMiddleware');
const { fetchEmails } = require('../services/mail');   // Gmail, Outlook or IMAP
const { analyseEmail } = require('../services/threatService');
const { getScanHistory, saveEmailScan, getThreatOverride, query, getSystemSetting } = require('../database/db');
const { getScanContext } = require('../database/db');

const router = express.Router();

// ── GET /analytics/dashboard ─────────────────────────────────
// 1. Scan the newest emails in the mailbox and save the results (if the mailbox is
//    reachable; a failure here never hides the numbers already saved).
// 2. Count everything from the saved scans of the last 30 days: newest scan of each
//    email, with user/admin level changes applied, quarantined emails included.
const { recordToEmail, nptDay, NPT_MS } = require('../services/threatRecords');
const REASON_GROUPS = [
  [/look-alike|lookalike/i, 'Look-alike domain'], [/display name|impersonat/i, 'Impersonation'], [/reply-to/i, 'Reply-To mismatch'],
  [/hidden link/i, 'Hidden link'], [/payment|bank details|invoice|wire/i, 'Payment fraud'], [/new domain/i, 'New domain'],
  [/attachment/i, 'Risky attachment'], [/spf|dkim|dmarc|authentication/i, 'Failed sender checks'], [/ip address|ip-address/i, 'IP-address link'],
  [/safe browsing/i, 'Known bad link'], [/global block list/i, 'Blocked domain'], [/ML Classifier|phishing keyword|urgen/i, 'Phishing wording'],
  [/link/i, 'Suspicious link'],
];
const groupOf = (reason) => (REASON_GROUPS.find(([re]) => re.test(reason)) || [null, 'Other'])[1];

router.get('/analytics/dashboard', requireAuth, async (req, res) => {
  const userId = req.session.user.id;
  let scanError = null;
  try {
    const scanLimit = parseInt(await getSystemSetting('max_emails_scan')) || 100;
    const emails = await fetchEmails(req.session.user, scanLimit);
    const seen = new Set();
    const unique = emails.filter(e => !seen.has(e.id) && seen.add(e.id));
    try { await require('../services/attachmentScanner').prepare(req.session.user, unique); } catch (e) { console.warn('[attachments]', e.message); }
    const scanCtx = await getScanContext(userId);
    for (const email of unique) {
      try { await saveEmailScan(email, await analyseEmail(email, scanCtx), userId); } catch (_) { /* one bad email never stops the rest */ }
    }
  } catch (err) { scanError = err.message; }

  try {
    const all = (await require('../database/db').getUserThreatRecords(userId, 30)).map(recordToEmail);
    const lv = (l) => all.filter(e => e.threat.level === l);
    const dangerous = lv('dangerous'), suspicious = lv('suspicious'), safe = lv('safe');
    const threats = [...dangerous, ...suspicious];

    // Last 7 days, by the day each email arrived (Nepal time)
    const labels = [], keys = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date(Date.now() + NPT_MS - i * 864e5);
      keys.push(d.toISOString().slice(0, 10));
      labels.push(d.toLocaleDateString('en-US', { weekday: 'short', timeZone: 'UTC' }));
    }
    const threatData = keys.map(() => 0), safeData = keys.map(() => 0);
    for (const e of all) {
      const k = keys.indexOf(nptDay(e.date) || nptDay(e.threat?.scannedAt));
      if (k < 0) continue;
      if (e.threat.level === 'safe') safeData[k]++; else threatData[k]++;
    }

    // What made emails threats (threats only, one count per email per kind of reason)
    const groups = {};
    for (const e of threats) for (const g of new Set((e.threat.reasons || []).map(groupOf))) groups[g] = (groups[g] || 0) + 1;
    const top = Object.entries(groups).sort((a, b) => b[1] - a[1]).slice(0, 6);

    const sub = (k) => threats.filter(e => (e.threat.subType || 'phishing') === k).length;
    res.json({
      success: true,
      period: '30 days',
      scanError,
      stats: {
        totalEmails: all.length, dangerous: dangerous.length, suspiciousEmails: suspicious.length, safeEmails: safe.length,
        threatsBlocked: threats.filter(e => e.blocked).length, quarantined: threats.filter(e => e.quarantined).length,
      },
      threatSubtypes: { phishing: sub('phishing'), malware_link: sub('malware_link'), spoofed_sender: sub('spoofed_sender'), other: sub('other') },
      charts: {
        trend: { labels, data: threatData, safe: safeData },
        types: { labels: top.map(t => t[0]), data: top.map(t => t[1]) },
      },
      recentThreats: threats.sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0)).slice(0, 5).map(e => ({
        id: e.id, from: e.from, subject: e.subject, level: e.threat.level, score: e.threat.score,
        reasons: (e.threat.reasons || []).slice(0, 2), quarantined: e.quarantined,
      })),
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message, scanError });
  }
});

// ── GET /api/analytics/insights — which checks fire, riskiest domains, MITRE, response ──
router.get('/analytics/insights', requireAuth, async (req, res) => {
  try {
    const db = require('../database/db');
    const { summarise } = require('../services/insights');
    const [rows, response] = await Promise.all([db.getInsightRows(req.session.user.id), db.getResponseCounts(req.session.user.id)]);
    res.json({ success: true, ...summarise(rows), response });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── GET /api/senders/profile?address= — history with one sender ──
router.get('/senders/profile', requireAuth, async (req, res) => {
  try {
    const profile = await require('../database/db').getSenderProfile(req.session.user.id, req.query.address);
    if (!profile) return res.status(400).json({ success: false, error: 'address required' });
    res.json({ success: true, profile });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

module.exports = router;
