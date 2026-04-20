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
// Uses Groq (same provider as rest of Genjutsu) to craft replies
// that READ the full conversation history before responding —
// making each reply contextually aware of what the scammer said.
// conversationHistory: array of { direction: 'inbound'|'outbound', body: string }
async function generateAIReply(scammerMessage, subject, repliesSent, conversationHistory = [], userName = 'Nami', senderEmail = '') {
  if (!process.env.GROQ_API_KEY) return getFallbackReply(repliesSent);

  const stage = repliesSent === 0
    ? 'initial interest — ask for more details about the offer'
    : repliesSent <= 2
    ? 'excited but confused — ask clarifying questions, mention your solicitor nephew'
    : repliesSent <= 4
    ? 'eager but having banking trouble — wrong account number, suggest an alternative method'
    : 'getting complicated — mention tax fees, need signed letters, want your church friends to join';

  // ── CHANGE: Use first name only for the persona sign-off ─────
  const firstName = userName.split(' ')[0] || userName;

  const systemPrompt = `You are ${firstName}, a friendly but confused 72-year-old retired teacher from Bristol, England.
You are responding to a scammer as a honeypot to waste their time as long as possible.
Your goal is to seem genuinely interested but always create delays, confusion, and complications.
Current stage: ${stage} (this is reply number ${repliesSent + 1}).

Rules:
- Read the ENTIRE conversation history carefully before replying
- Directly respond to the scammer's latest message — reference specific things they said
- Always ask at least one question that requires a detailed answer from them
- Add one new complication per reply (solicitor, banking issue, wrong details, tax question, church friends, computer trouble, etc.)
- Keep it 3-5 sentences, warm and conversational, slightly rambling
- Never reveal you are AI or a honeypot
- NEVER start the email with "Dear Scammer", "Dear User", "Dear Sender" or any generic label
- Start naturally, e.g. "Oh how wonderful!" or "Thank you so much for getting back to me!"
- Sign off as "${firstName}"`;

  // ── Use real scammer email as inbound label, user's real first name as outbound ──
  // senderEmail e.g. "evil@scammer.com" — strips display name wrapper if present
  const scammerLabel = (senderEmail || '').replace(/.*<(.+)>/, '$1').trim() || 'Sender';
  const historyText = conversationHistory.length > 0
    ? '\n\nConversation so far:\n' + conversationHistory.map(m =>
        `${m.direction === 'inbound' ? scammerLabel : firstName}: ${(m.body || '').substring(0, 300)}`
      ).join('\n\n')
    : '';

  const userPrompt = `Email subject: "${subject}"${historyText}

Scammer's latest message:
"${(scammerMessage || '').substring(0, 600)}"

Write ${firstName}'s reply. Respond specifically to what they just said and add a complication. Do NOT start with "Dear Scammer", "Dear User", or any generic label.`;

  return new Promise((resolve) => {
    const payload = JSON.stringify({
      model: 'llama-3.3-70b-versatile',
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user',   content: userPrompt }
      ],
      max_tokens:  250,
      temperature: 0.9
    });

    const options = {
      hostname: 'api.groq.com',
      path:     '/openai/v1/chat/completions',
      method:   'POST',
      headers: {
        'Content-Type':   'application/json',
        'Authorization':  `Bearer ${process.env.GROQ_API_KEY}`,
        'Content-Length': Buffer.byteLength(payload)
      }
    };

    const req = https.request(options, res => {
      let raw = '';
      res.on('data', c => { raw += c; });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(raw);
          if (parsed.error) {
            console.error('[Honeypot] Groq error:', parsed.error.message);
            return resolve(getFallbackReply(repliesSent));
          }
          const text = parsed?.choices?.[0]?.message?.content;
          resolve(text ? text.trim() : getFallbackReply(repliesSent));
        } catch {
          resolve(getFallbackReply(repliesSent));
        }
      });
    });

    req.on('error', () => resolve(getFallbackReply(repliesSent)));
    req.setTimeout(10000, () => { req.destroy(); resolve(getFallbackReply(repliesSent)); });
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
    const { emailBody, messageId: gmailMessageId } = req.body;

    // ── CHANGE: use first name only for persona sign-off ─────────
    const fullName  = req.session.user.name || '';
    const userName  = fullName.split(' ')[0] || req.session.user.email?.split('@')[0] || 'Nami';

    const reply     = await generateAIReply(emailBody || subject, subject, 0, [], userName, actualRecipient);
    const sessionId = `hp-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;

    // ── CHANGE: Fix 3 — store the Re: subject in the session from the start ──
    // Every subsequent poll reply reads session.subject, so storing it WITH
    // the Re: prefix here means the subject never changes across the whole conversation.
    const replySubject = subject.startsWith('Re:') ? subject : `Re: ${subject}`;
    await sendReply(
      req.session.user.accessToken,
      actualRecipient,
      replySubject,
      reply,
      {
        threadId:   threadId   || null,
        inReplyTo:  gmailMessageId || null,
        references: gmailMessageId || null
      }
    );

    const session = {
      session_id:    sessionId,
      user_id:       req.session.user.id,
      email_id:      emailId,
      thread_id:     threadId     || null,
      message_id:    gmailMessageId || null,
      sender_email:  actualRecipient,
      subject:       replySubject,  // ← CHANGE: store with Re: so all future poll replies use same subject
      replies_sent:  1,
      minutes_wasted: 0,
      started_at:    new Date().toISOString(),
      last_reply_at: new Date().toISOString(),
      status:        'active'
    };
    await saveHoneypotSession(session);

    // ── Save the scammer's original email as inbound message ──
    await saveHoneypotMessage({
      sessionId,
      direction:   'inbound',
      fromAddress: actualRecipient,
      body:        emailBody || subject || '(No body captured)',
      gmailMsgId:  emailId || null
    });

    // ── Save Honeypot's first reply as outbound message ───────
    await saveHoneypotMessage({
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
router.get('/honeypot/sessions', requireAuth, async (req, res) => {
  const sessions = await getHoneypotSessions(req.session.user.id);
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
  const sessions = await getHoneypotSessions(req.session.user.id);
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

      // Fetch full conversation history so AI reads entire context before replying
      let conversationHistory = [];
      try {
        const { getHoneypotMessages } = require('../database/db');
        const msgs = await getHoneypotMessages(session.session_id);
        conversationHistory = (msgs || []).map(m => ({ direction: m.direction, body: m.body }));
      } catch { conversationHistory = []; }

      // Generate AI reply — now with full conversation history for context
      const pollFullName = req.session.user.name || '';
      const pollUserName = pollFullName.split(' ')[0] || req.session.user.email?.split('@')[0] || 'Nami';
      const nextReply  = await generateAIReply(scammerText, session.subject, session.replies_sent, conversationHistory, pollUserName, session.sender_email);
      // ── CHANGE: subject already stored with Re: in session — use it directly, no recalculation ──
      const newSubject = session.subject;

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

      await updateHoneypotSession(session.session_id, {
        replies_sent:          session.replies_sent + 1,
        last_reply_at:         new Date().toISOString(),
        references_hdr:        newRefs,
        last_processed_msg_id: latestScammerMsg.id
      });

      // Save scammer's inbound message + our outbound reply to DB
      // so the admin panel conversation log stays up to date
      try {
        await saveHoneypotMessage({
          sessionId:   session.session_id,
          direction:   'inbound',
          fromAddress: session.sender_email,
          body:        scammerText,
          gmailMsgId:  latestScammerMsg.id
        });
        await saveHoneypotMessage({
          sessionId:   session.session_id,
          direction:   'outbound',
          fromAddress: null,
          body:        nextReply,
          gmailMsgId:  null
        });
      } catch (saveErr) {
        console.warn('[Honeypot] Could not save messages to DB:', saveErr.message);
      }

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
  const sessions = await getHoneypotSessions(req.session.user.id);
  const target   = sessions.find(s => s.session_id === req.params.sessionId);

  if (target && target.started_at) {
    const elapsedMinutes = Math.floor((Date.now() - new Date(target.started_at).getTime()) / 60000);
    if (typeof updateHoneypotSession === 'function') {
      await updateHoneypotSession(req.params.sessionId, { minutes_wasted: elapsedMinutes, status: 'ended' });
    }
  }

  await endHoneypotSession(req.params.sessionId);
  res.json({ success: true, message: 'Session ended' });
});

module.exports = router;
