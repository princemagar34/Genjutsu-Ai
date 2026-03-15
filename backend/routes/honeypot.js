// ============================================================
// routes/honeypot.js — Honeypot sessions (DB-backed)
// ============================================================
const express               = require('express');
const { requireAuth }       = require('../middleware/authMiddleware');
const { sendReply }         = require('../services/gmailService');
const { sendHoneypotAlert } = require('../services/telegramService');
const { saveHoneypotSession, getHoneypotSessions, endHoneypotSession } = require('../database/db');

const router = express.Router();

const REPLIES = [
  "Thank you for getting in touch! I'm very interested. Could you please provide more details?",
  "This sounds like a wonderful opportunity! Could you clarify the exact process for me?",
  "I'm very keen to proceed! My nephew is a solicitor and he said I need official documentation first.",
  "Brilliant news! However I'm having trouble with my online banking. Can we use an alternative method?",
  "I've forwarded this to my financial advisor. They need a few more details before I can proceed.",
  "Could you explain the process again step by step? I want to make absolutely sure I understand.",
  "I accidentally sent the payment to the wrong account number. How do I get it reversed?"
];

router.post('/honeypot/engage', requireAuth, async (req, res) => {
  const { emailId, senderEmail, subject } = req.body;
  if (!senderEmail) return res.status(400).json({ success: false, error: 'senderEmail required' });

  try {
    const reply     = REPLIES[Math.floor(Math.random() * REPLIES.length)];
    const sessionId = `hp-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;

    await sendReply(req.session.user.accessToken, senderEmail, `Re: ${subject}`, reply);

    const session = {
      session_id: sessionId, user_id: req.session.user.id,
      email_id: emailId, sender_email: senderEmail, subject,
      replies_sent: 1, minutes_wasted: 5, status: 'active'
    };
    saveHoneypotSession(session);
    sendHoneypotAlert({ senderEmail, subject }); // fire and forget

    res.json({ success: true, session, replySent: reply });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

router.get('/honeypot/sessions', requireAuth, (req, res) => {
  const sessions = getHoneypotSessions(req.session.user.id);
  res.json({
    success: true,
    totalSessions: sessions.length,
    totalMinutesWasted: sessions.reduce((a, s) => a + (s.minutes_wasted || 0), 0),
    sessions: sessions.map(s => ({
      emailId:       s.email_id,
      senderEmail:   s.sender_email,
      subject:       s.subject,
      startedAt:     s.started_at,
      repliesSent:   s.replies_sent,
      minutesWasted: s.minutes_wasted
    }))
  });
});

router.delete('/honeypot/sessions/:sessionId', requireAuth, (req, res) => {
  endHoneypotSession(req.params.sessionId);
  res.json({ success: true, message: 'Session ended' });
});

module.exports = router;
