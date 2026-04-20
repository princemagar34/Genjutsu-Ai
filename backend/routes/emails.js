// ============================================================
// routes/emails.js — Fetch, scan, save to DB, alert Telegram
// ============================================================
const express                      = require('express');
const { requireAuth }              = require('../middleware/authMiddleware');
const { fetchEmails }              = require('../services/gmailService');
const { scanEmails, analyseEmail } = require('../services/threatService');
const { sendThreatAlert }          = require('../services/telegramService');
const { saveEmailScan, getThreatOverride, getBlockedEmails, getHoneypotSessions, getSystemSetting } = require('../database/db');

const router     = express.Router();
const alertedIds = new Set();

router.get('/emails', requireAuth, async (req, res) => {
  try {
    // ── Read max scan limit from admin System Settings ────────
    const maxSetting = await getSystemSetting('max_emails_scan');
    const adminMax   = parseInt(maxSetting) || 50;
    const limit      = Math.min(parseInt(req.query.limit) || adminMax, adminMax);
    const filter = req.query.filter || 'all';
    const userId = req.session.user.id;

    const emails  = await fetchEmails(req.session.user.accessToken, limit);

    // Deduplicate by Gmail message ID — prevents same email appearing multiple times
    const seen = new Set();
    const uniqueEmails = emails.filter(e => {
      if (seen.has(e.id)) return false;
      seen.add(e.id);
      return true;
    });

    const scanned = await Promise.all(uniqueEmails.map(async email => {
      try { return { ...email, threat: await analyseEmail(email) }; }
      catch(e) { return { ...email, threat: { level:'safe', score:0, reasons:[], mlResult:{}, nlpFeatures:{} } }; }
    }));

    // ── Force loop messages of active honeypot sessions to dangerous ──
    // Only emails that are BOTH from the session sender AND in the same
    // Gmail thread as the session are forced dangerous.
    // This means a different unrelated email from the same scammer address
    // is NOT affected — only the actual back-and-forth conversation thread.
    try {
      const honeypotSessions = await getHoneypotSessions(userId);
      const activeSessions   = honeypotSessions.filter(s => s.status === 'active');

      if (activeSessions.length > 0) {
        scanned.forEach(email => {
          const emailSender   = (email.from     || '').toLowerCase().replace(/.*<(.+)>/, '$1').trim();
          const emailThreadId = (email.threadId || '').trim();

          const isLoopMessage = activeSessions.some(s => {
            const sessionSender   = (s.sender_email || '').toLowerCase().replace(/.*<(.+)>/, '$1').trim();
            const sessionThreadId = (s.thread_id    || '').trim();
            // Must match on BOTH sender email AND Gmail thread ID
            return emailSender === sessionSender && emailThreadId && emailThreadId === sessionThreadId;
          });

          if (isLoopMessage) {
            email.threat.level   = 'dangerous';
            email.threat.subType = 'phishing';
            email.threat.score   = Math.max(email.threat.score, 70);
            email.threat.reasons = ['Honeypot loop message — active scammer reply in session thread', ...email.threat.reasons];
          }
        });
      }
    } catch (_) { /* non-critical — don't break inbox scan if honeypot check fails */ }

    // Save to DB + fire Telegram for new threats (now async)
    for (const email of scanned) {
      await saveEmailScan(email, email.threat, userId);
      if (email.threat.level !== 'safe' && !alertedIds.has(email.id)) {
        alertedIds.add(email.id);
        sendThreatAlert({
          level: email.threat.level, subject: email.subject,
          from: email.from, score: email.threat.score, reasons: email.threat.reasons
        });
      }
    }

    // ── Merge user/admin overrides ────────────────────────────
    // After scanning, check if any email has been overridden by user or admin.
    // The override takes precedence over the scanner result.
    const withOverrides = await Promise.all(scanned.map(async email => {
      try {
        const dbEmailId = `${userId}-${email.id}`;
        const override  = await getThreatOverride(dbEmailId);
        if (override) {
          return {
            ...email,
            overrideLevel: override.new_level || null,
            adminRemark:   override.note       || null,
            overriddenBy:  override.overridden_by || null,
            threat: {
              ...email.threat,
              level:         override.new_level || email.threat.level,
              overrideLevel: override.new_level || null,
              adminRemark:   override.note      || null,
            }
          };
        }
      } catch (_) {}
      return email;
    }));

    const filtered = filter === 'all'
      ? withOverrides
      : withOverrides.filter(e => (e.threat.overrideLevel || e.threat.level) === filter);
    res.json({ success: true, total: filtered.length, emails: filtered });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── GET /emails/blocked — must be before /:id to avoid route conflict ──
router.get('/emails/blocked', requireAuth, async (req, res) => {
  try {
    const rows = await getBlockedEmails(req.session.user.id);
    res.json({ success: true, blocked: rows });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

router.get('/emails/:id', requireAuth, async (req, res) => {
  try {
    const maxSetting2 = await getSystemSetting('max_emails_scan');
    const emails = await fetchEmails(req.session.user.accessToken, parseInt(maxSetting2) || 100);
    const email  = emails.find(e => e.id === req.params.id);
    if (!email) return res.status(404).json({ success: false, error: 'Email not found' });
    res.json({ success: true, email: { ...email, threat: await analyseEmail(email) } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
