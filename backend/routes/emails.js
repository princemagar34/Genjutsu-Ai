// ============================================================
// routes/emails.js — Fetch, scan, save to DB, alert Telegram
// ============================================================
const express                      = require('express');
const { requireAuth }              = require('../middleware/authMiddleware');
const { fetchEmails, searchEmails, moveToSpam } = require('../services/mail');   // Gmail, Outlook or IMAP — picked per user
const { alertThreats }             = require('../services/alerts');
const { scanEmails, analyseEmail } = require('../services/threatService');
const teamAlerts                   = require('../services/teamAlerts');
const { saveEmailScan, getThreatOverride, getBlockedEmails, getHoneypotSessions, getSystemSetting } = require('../database/db');
const { getScanContext, getSettings, blockEmail, logUserActivity } = require('../database/db');

const router     = express.Router();
const alertedIds = new Set();

// ── Shared checking pipeline ─────────────────────────────────
// Runs every check on a batch of emails: attachments, the full analysis,
// honeypot loop detection and the user's/admin's overrides.
// record=true (normal inbox): also saves results, sends alerts and quarantines.
// record=false (searching older mail): checks only, so old emails don't change
// the 30-day dashboard numbers, send alerts or get moved to spam.
async function checkEmails(user, emails, { record = true } = {}) {
  const userId = user.id;

  // Deduplicate by message ID — prevents same email appearing multiple times
  const seen = new Set();
  const uniqueEmails = emails.filter(e => {
    if (seen.has(e.id)) return false;
    seen.add(e.id);
    return true;
  });

  try { await require('../services/attachmentScanner').prepare(user, uniqueEmails); } catch (e) { console.warn('[attachments]', e.message); }
  const scanCtx = await getScanContext(userId);
  const scanned = await Promise.all(uniqueEmails.map(async email => {
    try { return { ...email, threat: await analyseEmail(email, scanCtx) }; }
    catch(e) { return { ...email, threat: { level:'safe', score:0, reasons:[], mlResult:{}, nlpFeatures:{} } }; }
  }));

  // ── Force loop messages of active honeypot sessions to dangerous ──
  // Only emails that are BOTH from the session sender AND in the same
  // thread as the session are forced dangerous.
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

  // Save to DB + tell the team about new dangerous emails
  const userSettings = record ? await getSettings(userId).catch(() => ({})) : {};
  const newThreats = [];
  if (record) {
    for (const email of scanned) {
      await saveEmailScan(email, email.threat, userId);
      if (email.threat.level !== 'safe' && !alertedIds.has(email.id)) {
        alertedIds.add(email.id);
        newThreats.push({ subject: email.subject, from: email.from, level: email.threat.level, score: email.threat.score, reasons: email.threat.reasons });
        teamAlerts.threat({ userId, level: email.threat.level, subject: email.subject,
          from: email.from, score: email.threat.score, reasons: email.threat.reasons });
      }
    }
  }

  // ── Merge user/admin overrides (they take precedence over the scanner) ──
  const withOverrides = await Promise.all(scanned.map(async email => {
    try {
      const override = await getThreatOverride(`${userId}-${email.id}`);
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

  if (!record) return { emails: withOverrides, quarantined: [] };

  if (userSettings.discord_webhook && userSettings.real_time_alerts !== 0) alertThreats(userSettings.discord_webhook, newThreats);

  // ── Quarantine: move dangerous emails to spam (undo from the Blocked tab) ──
  // Only when automatic blocking is on, or the user's own rule says so. Never
  // emails in an active honeypot conversation, and never ones the user marked safe.
  const quarantined = [];
  try {
    const alreadyBlocked = new Set((await getBlockedEmails(userId)).map(b => b.email_id));
    for (const email of withOverrides) {
      const lvl = email.threat.overrideLevel || email.threat.level;
      const inHoneypot = (email.threat.reasons || [])[0]?.startsWith('Honeypot loop');
      const wanted = userSettings.auto_block ? lvl === 'dangerous' : !!email.threat.quarantineByRule;
      if (!wanted || inHoneypot || email.threat.overrideLevel === 'safe' || alreadyBlocked.has(`${userId}-${email.id}`)) continue;
      try {
        await moveToSpam(user, email.id);
        await blockEmail(userId, `${userId}-${email.id}`, email.id, email.from || '', email.subject || '', 'auto');
        await logUserActivity(userId, 'Quarantined automatically', `${email.subject || ''} — ${email.from || ''}`);
        quarantined.push({ id: email.id, subject: email.subject, from: email.from });
      } catch (err) { console.warn('[Quarantine] could not move', email.id, err.message); }
    }
  } catch (err) { console.warn('[Quarantine] skipped:', err.message); }
  const qIds = new Set(quarantined.map(q => q.id));
  return { emails: withOverrides.filter(e => !qIds.has(e.id)), quarantined };
}

const levelOf = e => e.threat.overrideLevel || e.threat.level;

router.get('/emails', requireAuth, async (req, res) => {
  try {
    // ── Read max scan limit from admin System Settings (default: latest 100) ──
    const maxSetting = await getSystemSetting('max_emails_scan');
    const adminMax   = parseInt(maxSetting) || 100;
    const limit      = Math.min(parseInt(req.query.limit) || adminMax, adminMax);
    const filter = req.query.filter || 'all';

    const fetched = await fetchEmails(req.session.user, limit);
    const { emails, quarantined } = await checkEmails(req.session.user, fetched, { record: true });

    const filtered = filter === 'all' ? emails : emails.filter(e => levelOf(e) === filter);
    res.json({ success: true, total: filtered.length, emails: filtered, quarantined });
    require('../database/db').markScan?.(req.session.user.id, null);
  } catch (err) {
    require('../database/db').markScan?.(req.session.user?.id, err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── GET /emails/search?q=…&limit=… — search the whole mailbox ──
// Finds older emails beyond the latest 100 (sender, subject or words in the
// email) and runs the same checks on them. Must be before /:id.
const searchHits = new Map();   // userId -> recent search timestamps (simple rate limit)
router.get('/emails/search', requireAuth, async (req, res) => {
  try {
    const q = String(req.query.q || '').replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, 200);
    if (q.length < 2) return res.status(400).json({ success: false, error: 'Type at least 2 characters to search.' });
    const limit = Math.max(1, Math.min(parseInt(req.query.limit) || 50, 50));

    const userId = req.session.user.id;
    const now = Date.now();
    const recent = (searchHits.get(userId) || []).filter(t => now - t < 60_000);
    if (recent.length >= 20) return res.status(429).json({ success: false, error: 'Too many searches — wait a minute and try again.' });
    recent.push(now); searchHits.set(userId, recent);

    const found = await searchEmails(req.session.user, q, limit);
    const { emails } = await checkEmails(req.session.user, found, { record: false });
    emails.sort((a, b) => new Date(b.date) - new Date(a.date));
    res.json({ success: true, query: q, total: emails.length, emails });
    try { await logUserActivity(userId, 'Searched mailbox', q.slice(0, 80)); } catch (_) {}
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
    const emails = await fetchEmails(req.session.user, parseInt(maxSetting2) || 100);
    const email  = emails.find(e => e.id === req.params.id);
    if (!email) return res.status(404).json({ success: false, error: 'Email not found' });
    try { await require('../services/attachmentScanner').prepare(req.session.user, [email]); } catch (e) { console.warn('[attachments]', e.message); }
    res.json({ success: true, email: { ...email, threat: await analyseEmail(email, await getScanContext(req.session.user.id)) } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
