// routes/analytics.js — async PostgreSQL version
const express         = require('express');
const { requireAuth } = require('../middleware/authMiddleware');
const { fetchEmails } = require('../services/gmailService');
const { analyseEmail } = require('../services/threatService');
const { getScanHistory, saveEmailScan, getThreatOverride, query, getSystemSetting } = require('../database/db');

const router = express.Router();

router.get('/analytics/dashboard', requireAuth, async (req, res) => {
  try {
    // ── Read max scan limit from admin System Settings ────────
    const maxSetting = await getSystemSetting('max_emails_scan');
    const scanLimit  = parseInt(maxSetting) || 100;
    const emails     = await fetchEmails(req.session.user.accessToken, scanLimit);

    // Deduplicate by Gmail message ID before scanning
    const seenIds = new Set();
    const uniqueEmails = emails.filter(e => {
      if (seenIds.has(e.id)) return false;
      seenIds.add(e.id);
      return true;
    });

    const scanned = await Promise.all(uniqueEmails.map(async email => {
      try { return { ...email, threat: await analyseEmail(email) }; }
      catch(e) { return { ...email, threat: { level:'safe', score:0, reasons:[], mlResult:{}, nlpFeatures:{} } }; }
    }));
    const userId  = req.session.user.id;

    // ── Save scans to DB so getScanHistory returns real data ──
    for (const email of scanned) {
      try { await saveEmailScan(email, email.threat, userId); }
      catch (_) { /* don't let a save failure break the response */ }
    }

    // ── Merge overrides so stats reflect user/admin reclassifications ──
    const withOverrides = await Promise.all(scanned.map(async email => {
      try {
        const dbEmailId = `${userId}-${email.id}`;
        const override  = await getThreatOverride(dbEmailId);
        if (override) {
          return {
            ...email,
            threat: { ...email.threat, level: override.new_level || email.threat.level }
          };
        }
      } catch (_) {}
      return email;
    }));

    const dangerous  = withOverrides.filter(e => e.threat.level === 'dangerous');
    const suspicious = withOverrides.filter(e => e.threat.level === 'suspicious');
    const safe       = withOverrides.filter(e => e.threat.level === 'safe');

    // ── Fixed 7-day range ─────────────────────────────────────
    const range   = 7;
    const history = await getScanHistory(userId, range);

    const labels     = [];
    const threatData = [];
    const safeData   = [];

    // Nepal is UTC+5:45. Cloud Run runs in UTC, so new Date() gives UTC dates.
    // Without this offset, dates near midnight NPT fall on the wrong day in the chart.
    const NPT_OFFSET_MS = (5 * 60 + 45) * 60 * 1000;

    for (let i = range - 1; i >= 0; i--) {
      // Compute today's date in NPT, then subtract i days
      const nowNPT = new Date(Date.now() + NPT_OFFSET_MS);
      nowNPT.setUTCHours(0, 0, 0, 0);
      nowNPT.setUTCDate(nowNPT.getUTCDate() - i);
      const key   = nowNPT.toISOString().split('T')[0]; // YYYY-MM-DD in NPT
      const label = nowNPT.toLocaleDateString('en-US', { weekday: 'short' });

      const row = history.find(h => {
        const rowDate = h.scan_date instanceof Date
          ? h.scan_date.toISOString().split('T')[0]
          : String(h.scan_date).split('T')[0];
        return rowDate === key;
      });

      labels.push(label);
      const dangerous  = row ? parseInt(row.dangerous  || 0) : 0;
      const suspicious = row ? parseInt(row.suspicious || 0) : 0;
      threatData.push(dangerous + suspicious);
      // 'safe' column is now explicitly returned by getScanHistory
      safeData.push(row ? parseInt(row.safe || 0) : 0);
    }

    // ── Pie chart — real reason counts from scanned emails ───
    const typeCount = {};
    scanned.forEach(e => {
      e.threat.reasons.forEach(r => {
        const key = r.split(':')[0].trim();
        typeCount[key] = (typeCount[key] || 0) + 1;
      });
    });

    // ── Threat sub-type counts — powers the 4 Threat Analysis cards ──
    // Reads threat_subtype from scan_results so the counts reflect real
    // sub-classification (phishing, malware_link, spoofed_sender, other).
    // Falls back to 0 for any subtype not yet present in the DB.
    let threatSubtypes = { phishing: 0, malware_link: 0, spoofed_sender: 0, other: 0 };
    try {
      const subtypeRes = await query(`
        SELECT COALESCE(sr.threat_subtype, 'phishing') AS subtype,
               COUNT(DISTINCT e.gmail_message_id)       AS count
        FROM scan_results sr
        JOIN emails e ON sr.email_id = e.email_id
        WHERE e.user_id        = $1
          AND sr.threat_detected = 1
          AND e.gmail_message_id IS NOT NULL
        GROUP BY sr.threat_subtype
      `, [userId]);
      subtypeRes.rows.forEach(row => {
        const key = row.subtype || 'phishing';
        if (threatSubtypes.hasOwnProperty(key)) {
          threatSubtypes[key] = parseInt(row.count);
        } else {
          threatSubtypes.other += parseInt(row.count);
        }
      });
    } catch (_) { /* non-critical — don't break dashboard if query fails */ }

    res.json({
      success: true,
      stats: {
        totalEmails: scanned.length, threatsBlocked: dangerous.length,
        safeEmails: safe.length, suspiciousEmails: suspicious.length, dangerous: dangerous.length
      },
      threatSubtypes,   // ← NEW: { phishing: N, malware_link: N, spoofed_sender: N, other: N }
      charts: {
        trend: { labels, data: threatData, safe: safeData },
        types: { labels: Object.keys(typeCount).slice(0, 6), data: Object.values(typeCount).slice(0, 6) }
      },
      recentThreats: [...dangerous, ...suspicious].slice(0, 5).map(e => ({
        id: e.id, from: e.from, subject: e.subject,
        level: e.threat.level, score: e.threat.score, reasons: e.threat.reasons.slice(0, 2)
      }))
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
