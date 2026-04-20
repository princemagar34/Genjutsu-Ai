// routes/threats.js — async PostgreSQL version
const express                = require('express');
const { requireAuth }        = require('../middleware/authMiddleware');
const { fetchEmails, moveToSpam, createSpamFilter, removeFromSpam } = require('../services/gmailService');
const { scanEmails, analyseEmail } = require('../services/threatService');
const { generateUserReport } = require('../services/reportService');
const { getReportData, getThreatOverride, userOverrideThreatLevel, blockEmail, unblockEmail, getSystemSetting } = require('../database/db');

const router = express.Router();

router.get('/threats', requireAuth, async (req, res) => {
  try {
    // ── Read max scan limit from admin System Settings ────────
    const maxSetting = await getSystemSetting('max_emails_scan');
    const scanLimit  = parseInt(maxSetting) || 150;
    const emails     = await fetchEmails(req.session.user.accessToken, scanLimit);
    const scanned = await Promise.all(emails.map(async email => {
      try { return { ...email, threat: await analyseEmail(email) }; }
      catch(e) { return { ...email, threat: { level:'safe', score:0, reasons:['Parse error'], mlResult:{}, nlpFeatures:{} } }; }
    }));

    // ── Merge admin overrides ─────────────────────────────────
    // For each threat email, look up any admin override in the DB.
    // If found: surface the overridden level and admin remark to the user.
    // The override does NOT re-run the scanner — it just adjusts what the user sees.
    const threatsRaw = scanned.filter(e => e.threat.level !== 'safe');
    const threats = await Promise.all(threatsRaw.map(async email => {
      try {
        const override = await getThreatOverride(email.id);
        if (override) {
          return {
            ...email,
            // Expose override fields at the top level so the user portal can
            // read them as email.adminRemark and email.overrideLevel
            adminRemark:   override.note       || null,
            overrideLevel: override.new_level  || null,
            overriddenBy:  override.overridden_by || null,
            overriddenAt:  override.overridden_at || null,
            threat: {
              ...email.threat,
              // Also nest them inside threat so email.threat.adminRemark works
              adminRemark:   override.note      || null,
              overrideLevel: override.new_level || null,
              // If admin changed the level, reflect it in the displayed level
              level: override.new_level || email.threat.level,
            }
          };
        }
      } catch (_) {
        // getThreatOverride failure should never break the whole response
      }
      return email;
    }));

    // Re-filter: if admin overrode a threat to 'safe', remove it from the list
    const visibleThreats = threats
      .filter(e => e.threat.level !== 'safe')
      .sort((a, b) => {
        // Sort by date descending (newest first)
        const dateA = new Date(a.date || 0).getTime();
        const dateB = new Date(b.date || 0).getTime();
        if (dateB !== dateA) return dateB - dateA;
        // Fallback: higher score first if same date
        return b.threat.score - a.threat.score;
      });

    res.json({
      success: true,
      summary: {
        total:      visibleThreats.length,
        dangerous:  visibleThreats.filter(e => e.threat.level === 'dangerous').length,
        suspicious: visibleThreats.filter(e => e.threat.level === 'suspicious').length
      },
      threats: visibleThreats
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

router.get('/threats/summary', requireAuth, async (req, res) => {
  try {
    const maxSetting2 = await getSystemSetting('max_emails_scan');
    const emails      = await fetchEmails(req.session.user.accessToken, parseInt(maxSetting2) || 100);
    const scanned = await scanEmails(emails);
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

router.get('/threats/report', requireAuth, async (req, res) => {
  try {
    const user       = req.session.user;
    const reportData = await getReportData(user.id);
    generateUserReport(res, user, reportData);
  } catch (err) {
    console.error('PDF report error:', err.message);
    res.status(500).json({ success: false, error: 'Could not generate report: ' + err.message });
  }
});

// ── POST /api/threats/:id/reclassify — user self-override ────
// Users can reclassify their own emails without admin access.
// This creates a user-level override stored separately from admin overrides.
router.post('/threats/:id/reclassify', requireAuth, async (req, res) => {
  const { newLevel, note } = req.body;
  const userId = req.session.user.id;
  if (!newLevel || !['safe','suspicious','dangerous'].includes(newLevel))
    return res.status(400).json({ success: false, error: 'newLevel must be safe, suspicious, or dangerous.' });
  try {
    // DB stores email_id as `${userId}-${gmailMessageId}` (see saveEmailScan)
    // The frontend sends the raw Gmail message ID, so we construct the DB key here
    const dbEmailId = `${userId}-${req.params.id}`;
    await userOverrideThreatLevel(dbEmailId, newLevel, userId, note || '');
    res.json({ success: true, message: `Email reclassified as ${newLevel}.` });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── POST /api/emails/:id/block ────────────────────────────────
// 1. Moves the email to Gmail SPAM (real block in Gmail)
// 2. Creates a Gmail filter so future emails from this sender go to spam
// 3. Saves to blocked_emails table in DB so Genjutsu Blocked tab works
router.post('/emails/:id/block', requireAuth, async (req, res) => {
  const userId = req.session.user.id;
  const { senderEmail, subject } = req.body;
  const gmailMsgId = req.params.id;
  const dbEmailId  = `${userId}-${gmailMsgId}`;
  try {
    // 1. Move to spam in Gmail
    await moveToSpam(req.session.user.accessToken, gmailMsgId);
    // 2. Create Gmail filter for future emails from this sender
    if (senderEmail) {
      try { await createSpamFilter(req.session.user.accessToken, senderEmail); }
      catch (_) { /* filter creation can fail if duplicate — non-critical */ }
    }
    // 3. Save to Genjutsu DB
    await blockEmail(userId, dbEmailId, gmailMsgId, senderEmail || '', subject || '');
    res.json({ success: true, message: 'Email moved to spam and sender filtered.' });
  } catch (err) {
    console.error('[Block] Error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── DELETE /api/emails/:id/block — unblock ────────────────────
// Restores email to inbox in Gmail and removes from DB blocked list
router.delete('/emails/:id/block', requireAuth, async (req, res) => {
  const userId     = req.session.user.id;
  const gmailMsgId = req.params.id;
  const dbEmailId  = `${userId}-${gmailMsgId}`;
  try {
    // Restore to inbox in Gmail
    await removeFromSpam(req.session.user.accessToken, gmailMsgId);
    // Remove from Genjutsu DB
    await unblockEmail(userId, dbEmailId);
    res.json({ success: true, message: 'Email restored to inbox.' });
  } catch (err) {
    console.error('[Unblock] Error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});


module.exports = router;
