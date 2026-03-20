// ============================================================
// routes/honeypot.js — Honeypot with auto-continuation loop
// ============================================================
const express               = require('express');
const { requireAuth }       = require('../middleware/authMiddleware');
const { sendReply, getGmailClient } = require('../services/gmailService');
const { sendHoneypotAlert } = require('../services/telegramService');
const {
  saveHoneypotSession, getHoneypotSessions,
  endHoneypotSession, updateHoneypotSession,
  saveHoneypotMessage
} = require('../database/db');

const router = express.Router();

const https = require('https');

// ── Fallback replies if AI is unavailable ─────────────────────
// Ordered to escalate naturally and waste maximum time
const FALLBACK_REPLIES = [
  "Thank you for getting in touch! This sounds very interesting. Could you please provide more details about the process?",
  "I'm very keen to proceed! My nephew is a solicitor and he said I need official documentation first. Can you send that?",
  "Brilliant news! However I'm having a little trouble with my online banking at the moment. Could we use an alternative method?",
  "I've forwarded everything to my financial advisor. She needs just a few more details before I can proceed. What is your full name and contact number?",
  "I'm so sorry for the delay! My computer has been playing up. Could you explain the process again step by step? I want to make absolutely sure I understand.",
  "I accidentally transferred the money to the wrong account number. My bank says they need a reference code from you to reverse it. Could you help?",
  "My solicitor says there may be a small tax fee before the funds can be released. Is that normal? How much are we talking?",
  "I've spoken to my bank and they need a signed letter of authority from you. Could you post that to me? I don't trust email for important documents.",
  "I'm so excited about this! I've told my friends at the church group and they want to join too. Can multiple people participate?",
  "I think I may have filled in the wrong account details. Could we start the process again from the beginning? I want to make sure everything is correct."
];

function getFallbackReply(repliesSent) {
  return FALLBACK_REPLIES[repliesSent % FALLBACK_REPLIES.length];
}

// ── AI-powered contextual reply generator ─────────────────────
// Uses Gemini to craft a reply that directly responds to what the
// scammer said — making it convincing and situation-specific
async function generateAIReply(scammerMessage, subject, repliesSent) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return getFallbackReply(repliesSent);

  // Build persona context that escalates with each reply
  const stage = repliesSent === 0
    ? 'initial interest — ask for more details'
    : repliesSent <= 2
    ? 'excited but confused — ask clarifying questions, mention a solicitor nephew'
    : repliesSent <= 4
    ? 'eager but having banking trouble — suggest alternative methods, wrong account number'
    : 'getting complicated — mention tax fees, need signed letters, tell them about church friends';

  const systemPrompt = `You are Honeypot, a friendly but confused 72-year-old retired teacher from Bristol, England.
You are responding to a scam email as a honeypot to waste the scammer's time.
Your goal is to seem genuinely interested but always create delays, confusion, and complications.
Current conversation stage: ${stage} (reply number ${repliesSent + 1}).

Rules:
- Stay completely in character as Honeypot — warm, slightly naive, easily confused
- Directly respond to what the scammer just said (don't ignore their message)
- Always ask at least one question that requires a detailed answer
- Add one complication (solicitor, banking issue, wrong details, tax question, etc.)
- Keep it 3-5 sentences, conversational, no formal language
- Never reveal you are AI or a honeypot
- Sign off as "Honeypot"`;

  const userPrompt = `The scammer sent me this email with subject "${subject}":
"${(scammerMessage || '').substring(0, 600)}"

Write my reply as Honeypot. Make it respond specifically to what they said.`;

  return new Promise((resolve) => {
    const payload = JSON.stringify({
      contents: [{ parts: [{ text: `${systemPrompt}

User: ${userPrompt}` }] }],
      generationConfig: { maxOutputTokens: 200, temperature: 0.9 }
    });

    const options = {
      hostname: 'generativelanguage.googleapis.com',
      path: `/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
    };

    const req = https.request(options, res => {
      let raw = '';
      res.on('data', c => { raw += c; });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(raw);
          const text   = parsed?.candidates?.[0]?.content?.parts?.[0]?.text;
          resolve(text ? text.trim() : getFallbackReply(repliesSent));
        } catch {
          resolve(getFallbackReply(repliesSent));
        }
      });
    });

    req.on('error', () => resolve(getFallbackReply(repliesSent)));
    req.setTimeout(8000, () => { req.destroy(); resolve(getFallbackReply(repliesSent)); });
    req.write(payload);
    req.end();
  });
}

// ── POST /honeypot/engage ─────────────────────────────────────
router.post('/honeypot/engage', requireAuth, async (req, res) => {
  const { emailId, senderEmail, replyTo, subject, threadId } = req.body;
  if (!senderEmail) return res.status(400).json({ success: false, error: 'senderEmail required' });

  const actualRecipient = replyTo || senderEmail;

  try {
    // Generate AI reply contextual to the scammer's actual email content
    const { emailBody } = req.body; // frontend should pass the email body/snippet
    const reply     = await generateAIReply(emailBody || subject, subject, 0);
    const sessionId = `hp-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;

    await sendReply(req.session.user.accessToken, actualRecipient, `Re: ${subject}`, reply);

    const session = {
      session_id:    sessionId,
      user_id:       req.session.user.id,
      email_id:      emailId,
      thread_id:     threadId || null,
      sender_email:  actualRecipient,
      subject,
      replies_sent:  1,
      minutes_wasted: 0,
      started_at:    new Date().toISOString(),
      last_reply_at: new Date().toISOString(),
      status:        'active'
    };
    saveHoneypotSession(session);

    // ── Save the scammer's original email as inbound message ──
    saveHoneypotMessage({
      sessionId,
      direction:   'inbound',
      fromAddress: actualRecipient,
      body:        emailBody || subject || '(No body captured)',
      gmailMsgId:  emailId || null
    });

    // ── Save Honeypot's first reply as outbound message ───────
    saveHoneypotMessage({
      sessionId,
      direction:   'outbound',
      fromAddress: req.session.user.email,
      body:        reply,
      gmailMsgId:  null
    });

    sendHoneypotAlert({ senderEmail: actualRecipient, subject });

    res.json({ success: true, session, replySent: reply });
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
router.get('/honeypot/sessions', requireAuth, (req, res) => {
  const sessions = getHoneypotSessions(req.session.user.id);
  const now      = Date.now();

  const enriched = sessions.map(s => {
    const startedAt     = s.started_at ? new Date(s.started_at).getTime() : now;
    const elapsedMs     = s.status === 'active' ? now - startedAt : (s.minutes_wasted * 60000);
    const minutesWasted = s.status === 'active'
      ? Math.floor(elapsedMs / 60000)
      : (s.minutes_wasted || 0);

    return {
      sessionId:   s.session_id,
      emailId:     s.email_id,
      threadId:    s.thread_id,
      senderEmail: s.sender_email,
      subject:     s.subject,
      startedAt:   s.started_at,
      lastReplyAt: s.last_reply_at,
      repliesSent: s.replies_sent,
      minutesWasted,
      status:      s.status
    };
  });

  const totalMinutesWasted  = enriched.reduce((a, s) => a + s.minutesWasted, 0);
  const activeConversations = sessions.filter(s => s.status === 'active').length;
  const scammersDetected    = sessions.length; // every session = one scammer caught

  res.json({
    success: true,
    totalSessions: sessions.length,
    totalMinutesWasted,
    activeConversations,
    scammersDetected,
    victimsProtected: scammersDetected, // keep for backwards compat
    sessions: enriched
  });
});

// ── In-memory lock — prevents two simultaneous polls processing the same session
const pollLock = new Set();

// ── POST /honeypot/poll ───────────────────────────────────────
router.post('/honeypot/poll', requireAuth, async (req, res) => {
  const sessions = getHoneypotSessions(req.session.user.id);
  const active   = sessions.filter(s => s.status === 'active');

  if (active.length === 0) return res.json({ success: true, checked: 0, replied: 0 });

  const gmail     = getGmailClient(req.session.user.accessToken);
  let   repliedTo = 0;
  const results   = [];

  for (const session of active) {
    // Skip if another poll call is already processing this session
    if (pollLock.has(session.session_id)) continue;
    pollLock.add(session.session_id);

    try {
      // lastReplyTime in ms — only look for messages AFTER this moment
      const lastReplyTime = new Date(session.last_reply_at || session.started_at).getTime();

      // Add a 10-second buffer: ignore anything that arrived within 10s of our
      // last reply — this prevents our own just-sent reply from being detected
      // as a new incoming message (especially when testing with your own account)
      const cutoffTime = lastReplyTime + 10000;
      if (Date.now() < cutoffTime) {
        pollLock.delete(session.session_id);
        continue;
      }

      // Search INBOX only — explicitly exclude Sent folder
      const senderRaw = session.sender_email.replace(/.*<(.+)>/, '$1').trim();
      const searchRes = await gmail.users.messages.list({
        userId: 'me',
        q:      `from:${senderRaw} in:inbox -in:sent`,
        maxResults: 10
      });

      const msgs             = searchRes.data.messages || [];
      let   latestScammerMsg = null;
      let   latestTimestamp  = 0;
      const lastProcessedId  = session.last_processed_msg_id || null;

      for (const msg of msgs) {
        // Skip the message we already replied to
        if (msg.id === lastProcessedId) continue;

        const detail = await gmail.users.messages.get({
          userId: 'me', id: msg.id, format: 'metadata',
          metadataHeaders: ['From', 'Date']
        });

        // Hard-reject anything with the SENT label — these are OUR outgoing replies,
        // not the scammer's incoming messages
        const labels = detail.data.labelIds || [];
        if (labels.includes('SENT')) continue;

        // Hard-reject if From header matches our own email (self-send test scenario)
        const myEmail   = (req.session.user.email || '').toLowerCase();
        const fromHeader = (
          detail.data.payload?.headers?.find(h => h.name.toLowerCase() === 'from')?.value || ''
        ).toLowerCase();
        if (myEmail && fromHeader.includes(myEmail)) continue;

        const ts = parseInt(detail.data.internalDate || '0');

        // Must be newer than our last reply + buffer
        if (ts > cutoffTime && ts > latestTimestamp) {
          latestTimestamp  = ts;
          latestScammerMsg = detail.data;
        }
      }

      if (!latestScammerMsg) {
        pollLock.delete(session.session_id);
        continue; // no genuine new reply from scammer yet
      }

      // Get full body of the scammer's reply for AI context
      let scammerText = '';
      try {
        const full  = await gmail.users.messages.get({ userId: 'me', id: latestScammerMsg.id, format: 'full' });
        const parts = full.data.payload?.parts || [];
        const tp    = parts.find(p => p.mimeType === 'text/plain');
        scammerText = tp?.body?.data
          ? Buffer.from(tp.body.data, 'base64').toString('utf-8').substring(0, 600)
          : (full.data.snippet || '');
      } catch { scammerText = latestScammerMsg.snippet || ''; }

      // Generate AI reply contextual to what the scammer wrote
      const nextReply  = await generateAIReply(scammerText, session.subject, session.replies_sent);
      const newSubject = session.subject.startsWith('Re:') ? session.subject : `Re: ${session.subject}`;

      // Get the scammer's latest Message-ID for In-Reply-To threading
      let latestMsgId = '';
      try {
        const fullMsg = await gmail.users.messages.get({ userId: 'me', id: latestScammerMsg.id, format: 'metadata', metadataHeaders: ['Message-ID','Message-Id'] });
        const hdrs    = fullMsg.data.payload?.headers || [];
        latestMsgId   = (hdrs.find(h => h.name.toLowerCase() === 'message-id') || {}).value || '';
      } catch { latestMsgId = ''; }

      // Build growing References chain (tracks full conversation thread)
      const prevRefs     = session.references_hdr || session.message_id || '';
      const newRefs      = prevRefs ? `${prevRefs} ${latestMsgId}`.trim() : latestMsgId;

      await sendReply(
        req.session.user.accessToken,
        session.sender_email,
        newSubject,
        nextReply,
        {
          threadId:   session.thread_id,
          inReplyTo:  latestMsgId || session.message_id,
          references: newRefs
        }
      );

      updateHoneypotSession(session.session_id, {
        replies_sent:          session.replies_sent + 1,
        last_reply_at:         new Date().toISOString(),   // FIX: use actual send time, not scammer's message time
        references_hdr:        newRefs,
        last_processed_msg_id: latestScammerMsg.id         // FIX: track which message we replied to
      });

      repliedTo++;
      results.push({
        sessionId:    session.session_id,
        scammer:      session.sender_email,
        replySent:    nextReply,
        totalReplies: session.replies_sent + 1
      });

      console.log(`[Honeypot] Auto-replied to ${session.sender_email} (reply #${session.replies_sent + 1})`);
      sendHoneypotAlert({ senderEmail: session.sender_email, subject: `[Reply #${session.replies_sent + 1}] ${session.subject}` });

    } catch (err) {
      console.warn(`[Honeypot poll] Session ${session.session_id} error:`, err.message);
    } finally {
      pollLock.delete(session.session_id);
    }
  }

  res.json({ success: true, checked: active.length, replied: repliedTo, results });
});

// ── DELETE /honeypot/sessions/:sessionId ─────────────────────
router.delete('/honeypot/sessions/:sessionId', requireAuth, async (req, res) => {
  const sessions = getHoneypotSessions(req.session.user.id);
  const target   = sessions.find(s => s.session_id === req.params.sessionId);

  if (target && target.started_at) {
    const elapsedMinutes = Math.floor((Date.now() - new Date(target.started_at).getTime()) / 60000);
    if (typeof updateHoneypotSession === 'function') {
      updateHoneypotSession(req.params.sessionId, { minutes_wasted: elapsedMinutes, status: 'ended' });
    }
  }

  endHoneypotSession(req.params.sessionId);
  res.json({ success: true, message: 'Session ended' });
});

module.exports = router;
