// routes/analytics.js — async PostgreSQL version
const express         = require('express');
const { requireAuth } = require('../middleware/authMiddleware');
const { fetchEmails } = require('../services/mail');   // Gmail, Outlook or IMAP
const { analyseEmail } = require('../services/threatService');
const { getScanHistory, saveEmailScan, getThreatOverride, query, getSystemSetting } = require('../database/db');
const { getScanContext } = require('../database/db');

const router = express.Router();

// ── GET /analytics/dashboard ─────────────────────────────────
// Counts everything from the saved scans of the last 30 days: newest scan of each
// email, with user/admin level changes applied, quarantined emails included.
// New emails are checked in the background (see startInboxScan below).
const { recordToEmail, nptDay, NPT_MS } = require('../services/threatRecords');
const REASON_GROUPS = [
  [/look-alike|lookalike/i, 'Look-alike domain'], [/display name|impersonat/i, 'Impersonation'], [/reply-to/i, 'Reply-To mismatch'],
  [/hidden link/i, 'Hidden link'], [/payment|bank details|invoice|wire/i, 'Payment fraud'], [/new domain/i, 'New domain'],
  [/attachment/i, 'Risky attachment'], [/spf|dkim|dmarc|authentication/i, 'Failed sender checks'], [/ip address|ip-address/i, 'IP-address link'],
  [/safe browsing/i, 'Known bad link'], [/global block list/i, 'Blocked domain'], [/ML Classifier|phishing keyword|urgen/i, 'Phishing wording'],
  [/link/i, 'Suspicious link'],
];
const groupOf = (reason) => (REASON_GROUPS.find(([re]) => re.test(reason)) || [null, 'Other'])[1];

// The numbers come straight from the saved scans, so the dashboard answers in
// well under a second. Checking the mailbox for new emails runs in the
// background: only emails never scanned before are analysed (the inbox list,
// /api/emails, re-checks the rest), at most one scan per user at a time and at
// most one every 45 seconds. The answer says `scanning: true` while it runs so
// the page can ask again when it's done.
const SCAN_GAP_MS = 45 * 1000;
const SCAN_PARALLEL = 5;
const inboxScans = new Map();   // userId -> { running, lastStart, error }

async function scanNewEmails(user) {
  const userId = user.id;
  const scanLimit = parseInt(await getSystemSetting('max_emails_scan')) || 100;
  const emails = await fetchEmails(user, scanLimit);
  const seen = new Set();
  const unique = emails.filter(e => e && e.id && !seen.has(e.id) && seen.add(e.id));
  if (!unique.length) return;

  const { rows } = await query(
    'SELECT DISTINCT gmail_message_id FROM emails WHERE user_id = $1 AND gmail_message_id = ANY($2)',
    [userId, unique.map(e => e.id)]
  );
  const known = new Set(rows.map(r => r.gmail_message_id));
  const fresh = unique.filter(e => !known.has(e.id));
  if (!fresh.length) return;

  try { await require('../services/attachmentScanner').prepare(user, fresh); } catch (e) { console.warn('[attachments]', e.message); }
  const scanCtx = await getScanContext(userId);
  for (let i = 0; i < fresh.length; i += SCAN_PARALLEL) {
    await Promise.all(fresh.slice(i, i + SCAN_PARALLEL).map(async email => {
      try { await saveEmailScan(email, await analyseEmail(email, scanCtx), userId); } catch (_) { /* one bad email never stops the rest */ }
    }));
  }
}

function startInboxScan(req) {
  const userId = req.session.user.id;
  const state = inboxScans.get(userId) || {};
  if (state.running || Date.now() - (state.lastStart || 0) < SCAN_GAP_MS) return state;
  state.lastStart = Date.now();
  state.running = scanNewEmails(req.session.user)
    .then(() => { state.error = null; })
    .catch(err => { state.error = err.message; })
    .finally(() => {
      state.running = null;
      // A provider may have refreshed the mailbox token during the scan: keep it
      try { req.session.save(() => {}); } catch (_) {}
    });
  inboxScans.set(userId, state);
  return state;
}

router.get('/analytics/dashboard', requireAuth, async (req, res) => {
  const userId = req.session.user.id;
  const scan = startInboxScan(req);
  const scanError = scan.error || null;
  const scanning = !!scan.running;

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
      scanning,
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
