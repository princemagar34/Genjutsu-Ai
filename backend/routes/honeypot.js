// ============================================================
// routes/honeypot.js — Honeypot with auto-continuation loop
// ============================================================
const express               = require('express');
const { requireAuth }       = require('../middleware/authMiddleware');
const teamAlerts = require('../services/teamAlerts');
const {
  saveHoneypotSession, getHoneypotSessions,
  endHoneypotSession, updateHoneypotSession,
  saveHoneypotMessage, getSettings, logUserActivity, getHoneypotMessagesBulk,
  setHoneypotSessionsPaused
} = require('../database/db');
const nami = require('../services/nami');

const router = express.Router();
const runner = require('../services/honeypotRunner');
const { NO_REPLY } = require('../services/mail');

// ── POST /honeypot/engage ─────────────────────────────────────
router.post('/honeypot/engage', requireAuth, async (req, res) => {
  const { emailId, senderEmail, replyTo, subject, threadId } = req.body;
  if (!senderEmail) return res.status(400).json({ success: false, error: 'senderEmail required' });

  const actualRecipient = replyTo || senderEmail;

  try {
    // Already talking to this scammer about this email? Don't start a second conversation
    // (a double click, or pressing Engage again, used to send two replies).
    const open = (await getHoneypotSessions(req.session.user.id, true)).find(s => (s.status === 'active' || s.status === 'paused') &&
      ((emailId && s.email_id === emailId) || (threadId && s.thread_id === threadId) ||
       String(s.sender_email || '').toLowerCase() === String(actualRecipient).toLowerCase()));
    if (open) return res.status(409).json({ success: false, alreadyActive: true, sessionId: open.session_id,
      error: 'Nami is already talking to this scammer. See the conversation on the Honeypot page.' });

    // Never answer a no-reply address
    if (NO_REPLY.test(actualRecipient)) {
      const err = new Error('NO_REPLY_ADDRESS'); err.noReply = true; err.blockedAddress = actualRecipient; throw err;
    }

    const { emailBody, messageId: gmailMessageId } = req.body;
    let persona = req.body.persona;
    if (!nami.PERSONAS[persona]) persona = nami.personaOf((await getSettings(req.session.user.id).catch(() => ({}))).honeypot_persona);
    const sessionId = `hp-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;

    // The subject is stored with Re: from the start, so every reply keeps the same subject
    const replySubject = String(subject || '').startsWith('Re:') ? subject : `Re: ${subject || ''}`;

    // Nami doesn't answer at once: the first reply goes out at a random
    // "lottery" moment 15 min – 24 h from now (20–60 s in the demo)
    const replyDueAt = nami.drawReplyTime(Date.now(), { demo: req.session.user.provider === 'demo' }).toISOString();

    const session = {
      session_id:    sessionId,
      user_id:       req.session.user.id,
      email_id:      emailId,
      thread_id:     threadId     || null,
      message_id:    gmailMessageId || null,
      sender_email:  actualRecipient,
      subject:       replySubject,
      replies_sent:  0,
      minutes_wasted: 0,
      started_at:    new Date().toISOString(),
      last_reply_at: new Date().toISOString(),
      status:        'active'
    };
    await saveHoneypotSession(session);
    await updateHoneypotSession(sessionId, { persona, reply_due_at: replyDueAt, pending_msg_id: emailId || null,
      pending_msg_hdr: gmailMessageId || null, effort_counted: 1 });
    await logUserActivity(req.session.user.id, 'Engaged Nami', `${subject} — ${actualRecipient} (${nami.PERSONAS[persona].label})`);

    // The scammer's original email starts the conversation
    await saveHoneypotMessage({
      sessionId,
      direction:   'inbound',
      fromAddress: actualRecipient,
      body:        emailBody || subject || '(No body captured)',
      gmailMsgId:  emailId || null
    });

    teamAlerts.honeypot({ userId: req.session.user.id, senderEmail: actualRecipient, subject });

    res.json({ success: true, session: { ...session, persona }, replyDueAt });
  } catch (err) {
    if (err.noReply) {
      return res.status(400).json({
        success: false,
        noReplyBlocked: true,
        error: `This email has no Reply-To address — it is a real system email (${err.blockedAddress}), not a scammer. Honeypot only works on phishing emails with a real sender.`
      });
    }
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── GET /honeypot/sessions ────────────────────────────────────
router.get('/honeypot/sessions', requireAuth, async (req, res) => {
  const sessions = await getHoneypotSessions(req.session.user.id, true);   // ended ones too, for history + leaderboard
  const msgs     = await getHoneypotMessagesBulk(sessions.map(s => s.session_id)).catch(() => []);

  // "Time wasted" is the scammer's own effort (nami.effortMinutes): reading
  // Nami's messages and writing theirs. It is counted when each reply arrives.
  const enriched = sessions.map(s => ({
    sessionId:   s.session_id,
    emailId:     s.email_id,
    threadId:    s.thread_id,
    senderEmail: s.sender_email,
    subject:     s.subject,
    startedAt:   s.started_at,
    lastReplyAt: s.replies_sent ? s.last_reply_at : null,
    repliesSent: s.replies_sent || 0,
    scammerReplies: s.scammer_replies || 0,
    scammerWords:   s.scammer_words || 0,
    firstScammerAt: s.first_scammer_at,
    lastScammerAt:  s.last_scammer_at,
    minutesWasted:  s.minutes_wasted || 0,
    replyDueAt:  s.status === 'active' ? s.reply_due_at : null,
    status:      s.status,
    persona:     s.persona || 'teacher',
    personaLabel: (nami.PERSONAS[s.persona] || nami.PERSONAS.teacher).label,
    stopReason:  s.stop_reason || null,
    messages:    msgs.filter(m => m.session_id === s.session_id).map(m => ({ direction: m.direction, body: m.body, sentAt: m.sent_at }))
  }));

  const totalMinutesWasted  = enriched.reduce((a, s) => a + s.minutesWasted, 0);
  const activeConversations = sessions.filter(s => s.status === 'active').length;
  const pausedConversations = sessions.filter(s => s.status === 'paused').length;
  const scammersEngaged     = sessions.length;

  const monthStart = new Date(); monthStart.setDate(1); monthStart.setHours(0, 0, 0, 0);
  const leaderboard = {
    monthMinutes: enriched.filter(x => new Date(x.startedAt) >= monthStart).reduce((a, x) => a + x.minutesWasted, 0),
    longest:      [...enriched].sort((a, b) => b.minutesWasted - a.minutesWasted).slice(0, 5)
                    .map(({ messages, ...x }) => x),
    mostReplies:  enriched.reduce((m, x) => Math.max(m, x.scammerReplies || 0), 0)
  };

  res.json({
    success: true,
    leaderboard,
    personas: nami.personaSamples(),
    totalSessions: sessions.length,
    totalMinutesWasted,
    totalScammerReplies: enriched.reduce((a, s) => a + s.scammerReplies, 0),
    totalScammerWords:   enriched.reduce((a, s) => a + s.scammerWords, 0),
    activeConversations,
    pausedConversations,
    scammersEngaged,
    scammersDetected: scammersEngaged,   // older name, kept for compatibility
    victimsProtected: scammersEngaged,   // older name, kept for compatibility
    sessions: enriched
  });
});

// ── POST /honeypot/poll — the page asks for a check now ──────
// The server also does this every 2 minutes on its own (honeypotRunner),
// so conversations continue when nobody has Genjutsu open.
router.post('/honeypot/poll', requireAuth, async (req, res) => {
  try {
    const active = await getHoneypotSessions(req.session.user.id);
    if (!active.length) return res.json({ success: true, checked: 0, replied: 0 });
    const r = await runner.runForUser(req.session.user, active);
    res.json({ success: true, ...r });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── POST /honeypot/pause-all and /honeypot/resume-all ───────
router.post('/honeypot/pause-all', requireAuth, async (req, res) => {
  try {
    const n = await setHoneypotSessionsPaused(req.session.user.id, true);
    if (n) await logUserActivity(req.session.user.id, 'Paused all Nami conversations', `${n} paused`);
    res.json({ success: true, paused: n });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});
router.post('/honeypot/resume-all', requireAuth, async (req, res) => {
  try {
    const n = await setHoneypotSessionsPaused(req.session.user.id, false);
    if (n) await logUserActivity(req.session.user.id, 'Resumed Nami conversations', `${n} resumed`);
    res.json({ success: true, resumed: n });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── GET /honeypot/sessions/:sessionId/messages — user-facing ─
// Returns conversation messages for a session so the frontend can
// show the full honeypot chat inline without going to the admin panel.
router.get('/honeypot/sessions/:sessionId/messages', requireAuth, async (req, res) => {
  try {
    const { getHoneypotMessages, getHoneypotSessionById } = require('../database/db');
    // Verify this session belongs to the requesting user
    const session = await getHoneypotSessionById(req.params.sessionId);
    if (!session || session.user_id !== req.session.user.id) {
      return res.status(404).json({ success: false, error: 'Session not found.' });
    }
    const messages = await getHoneypotMessages(req.params.sessionId);
    res.json({
      success: true,
      messages: messages.map(m => ({
        id:        m.message_id,
        direction: m.direction,   // 'inbound' = scammer, 'outbound' = honeypot persona
        from:      m.from_address,
        body:      m.body,
        sentAt:    m.sent_at
      }))
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── DELETE /honeypot/sessions/:sessionId ─────────────────────
router.delete('/honeypot/sessions/:sessionId', requireAuth, async (req, res) => {
  const sessions = await getHoneypotSessions(req.session.user.id, true);
  const target   = sessions.find(s => s.session_id === req.params.sessionId);
  if (!target) return res.status(404).json({ success: false, error: 'Session not found.' });
  await endHoneypotSession(req.params.sessionId, 'Ended by you');
  await logUserActivity(req.session.user.id, 'Ended a Nami conversation', target.sender_email);
  res.json({ success: true, message: 'Session ended' });
});

// ── GET /honeypot/intel — details scammers gave away ─────────
// Bank accounts, wallets, phone numbers, links… pulled from their replies.
router.get('/honeypot/intel', requireAuth, async (req, res) => {
  try {
    const sessions = await getHoneypotSessions(req.session.user.id, true);
    const msgs = await getHoneypotMessagesBulk(sessions.map(s => s.session_id));
    const me = req.session.user.email;
    const perSession = sessions.map(s => {
      const inbound = msgs.filter(m => m.session_id === s.session_id && m.direction === 'inbound');
      const intel = nami.mergeIntel(inbound.map(m => nami.extractIntel(m.body, { exclude: [me, s.sender_email] })));
      return { sessionId: s.session_id, scammer: s.sender_email, subject: s.subject, intel };
    }).filter(x => Object.values(x.intel).some(v => v.length));
    res.json({ success: true, total: nami.mergeIntel(perSession.map(x => x.intel)), sessions: perSession });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

module.exports = router;
