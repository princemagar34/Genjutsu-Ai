// routes/threats.js — async PostgreSQL version
const db = require('../database/db');
const express                = require('express');
const { requireAuth }        = require('../middleware/authMiddleware');
const { fetchEmails, moveToSpam, createSpamFilter, removeFromSpam } = require('../services/mail');   // Gmail, Outlook or IMAP
const { scanEmails, analyseEmail } = require('../services/threatService');
const { generateUserReport } = require('../services/reportService');
const { getReportData, getThreatOverride, userOverrideThreatLevel, blockEmail, unblockEmail, getSystemSetting } = require('../database/db');
const { getScanContext, getEmailSender, addSafeSender, removeSafeSender, logUserActivity } = require('../database/db');

const router = express.Router();

// ── GET /threats — every threat Genjutsu found for you (last 90 days) ──
// Built from the saved scans, not by re-reading the inbox: quarantined emails sit in
// spam and would otherwise vanish from the counts. Admin overrides and remarks apply.
const { recordToEmail } = require('../services/threatRecords');

router.get('/threats', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const days = Math.min(365, Math.max(1, parseInt(req.query.days) || 90));
    let all;
    if ((await db.countUserScans(userId)) > 0) {
      all = (await db.getUserThreatRecords(userId, days)).map(recordToEmail);
    } else {
      // Nothing scanned yet (brand-new account): scan the inbox now
      const scanLimit = parseInt(await getSystemSetting('max_emails_scan')) || 150;
      const emails = await fetchEmails(req.session.user, scanLimit);
      try { await require('../services/attachmentScanner').prepare(req.session.user, emails); } catch (e) { console.warn('[attachments]', e.message); }
      const scanCtx = await getScanContext(userId);
      all = await Promise.all(emails.map(async email => {
        try { return { ...email, threat: await analyseEmail(email, scanCtx) }; }
        catch (e) { return { ...email, threat: { level: 'safe', score: 0, reasons: ['Parse error'] } }; }
      }));
    }
    const threats = all.filter(e => e.threat.level === 'dangerous' || e.threat.level === 'suspicious')
      .sort((a, b) => (new Date(b.date || 0) - new Date(a.date || 0)) || (b.threat.score - a.threat.score));

    const count = (k) => threats.filter(e => (e.threat.subType || 'phishing') === k).length;
    res.json({
      success: true,
      days,
      summary: {
        scanned:     all.length,
        total:       threats.length,
        dangerous:   threats.filter(e => e.threat.level === 'dangerous').length,
        suspicious:  threats.filter(e => e.threat.level === 'suspicious').length,
        quarantined: threats.filter(e => e.quarantined).length,
        types: { phishing: count('phishing'), malware_link: count('malware_link'), spoofed_sender: count('spoofed_sender'), other: count('other') },
      },
      threats,
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

router.get('/threats/summary', requireAuth, async (req, res) => {
  try {
    const rows = (await db.getUserThreatRecords(req.session.user.id, 90)).map(recordToEmail);
    const lv = (l) => rows.filter(e => e.threat.level === l).length;
    res.json({ success: true, total: rows.length, safe: lv('safe'), suspicious: lv('suspicious'), dangerous: lv('dangerous') });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

router.get('/threats/report', requireAuth, async (req, res) => {
  try {
    const user       = req.session.user;
    const reportData = await getReportData(user.id);
    let response;
    try { response = await require('../database/db').getResponseCounts(user.id); } catch (_) {}
    generateUserReport(res, user, reportData, { response });
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
    // Marking an email safe trusts its sender from now on; marking it a threat removes that trust
    let trusted = null;
    try {
      const sender = await getEmailSender(dbEmailId);
      if (sender) trusted = newLevel === 'safe' ? await addSafeSender(userId, sender) : (await removeSafeSender(userId, sender), null);
    } catch (_) {}
    await logUserActivity(userId, `Changed threat level to ${newLevel}`, trusted ? `trusted ${trusted}` : '');
    res.json({ success: true, message: `Email reclassified as ${newLevel}.`, trustedSender: trusted });
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
    await moveToSpam(req.session.user, gmailMsgId);
    // 2. Create Gmail filter for future emails from this sender
    if (senderEmail) {
      try { await createSpamFilter(req.session.user, senderEmail); }
      catch (_) { /* filter creation can fail if duplicate — non-critical */ }
    }
    // 3. Save to Genjutsu DB
    await blockEmail(userId, dbEmailId, gmailMsgId, senderEmail || '', subject || '');
    await logUserActivity(userId, 'Blocked sender', `${subject || ''} — ${senderEmail || ''}`);
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
    await removeFromSpam(req.session.user, gmailMsgId);
    // Remove from Genjutsu DB
    await unblockEmail(userId, dbEmailId);
    await logUserActivity(userId, 'Restored email to inbox', gmailMsgId);
    res.json({ success: true, message: 'Email restored to inbox.' });
  } catch (err) {
    console.error('[Unblock] Error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});


module.exports = router;
