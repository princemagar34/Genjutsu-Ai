// ============================================================
// routes/honeypot.js — Honeypot with auto-continuation loop
// ============================================================
const express               = require('express');
const { requireAuth }       = require('../middleware/authMiddleware');
const { sendReply, findLatestFrom } = require('../services/mail');   // Gmail, Outlook or IMAP
const teamAlerts = require('../services/teamAlerts');
const {
  saveHoneypotSession, getHoneypotSessions,
  endHoneypotSession, updateHoneypotSession,
  saveHoneypotMessage, getSettings, logUserActivity, getHoneypotMessagesBulk
} = require('../database/db');
const nami = require('../services/nami');

const router = express.Router();

const https = require('https');
const { groqRequestOptions } = require('../services/groqModel');

// ── AI-powered contextual reply generator ─────────────────────
// Uses Groq (same provider as rest of Genjutsu) to craft replies
// that READ the full conversation history before responding —
// making each reply contextually aware of what the scammer said.
// conversationHistory: array of { direction: 'inbound'|'outbound', body: string }
async function generateAIReply(scammerMessage, subject, repliesSent, conversationHistory = [], userName = 'Nami', senderEmail = '', persona = nami.DEFAULT_PERSONA, allowAI = true) {
  const firstNameFb = (userName.split(' ')[0] || userName);
  const fb = () => nami.fallbackReply(persona, repliesSent, firstNameFb);
  if (!process.env.GROQ_API_KEY || !allowAI) return fb();
  const clean = (t) => nami.sanitiseReply(t) || fb();   // never send anything that looks like real data

  const firstName = userName.split(' ')[0] || userName;
  const systemPrompt = nami.systemPrompt(persona, firstName, repliesSent);

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
      ...groqRequestOptions({ answerTokens: 250, temperature: 0.9 }),
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user',   content: userPrompt }
      ]
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
            return resolve(fb());
          }
          const text = parsed?.choices?.[0]?.message?.content;
          resolve(text ? clean(text) : fb());
        } catch {
          resolve(fb());
        }
      });
    });

    req.on('error', () => resolve(fb()));
    req.setTimeout(20000, () => { req.destroy(); resolve(fb()); });
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
    // Already talking to this scammer about this email? Don't start a second conversation
    // (a double click, or pressing Engage again, used to send two replies).
    const open = (await getHoneypotSessions(req.session.user.id)).find(s => s.status === 'active' &&
      ((emailId && s.email_id === emailId) || (threadId && s.thread_id === threadId) ||
       String(s.sender_email || '').toLowerCase() === String(actualRecipient).toLowerCase()));
    if (open) return res.status(409).json({ success: false, alreadyActive: true, sessionId: open.session_id,
      error: 'Nami is already talking to this scammer. See the conversation on the Honeypot page.' });

    // Generate AI reply contextual to the scammer's actual email content
    const { emailBody, messageId: gmailMessageId } = req.body;

    // ── CHANGE: use first name only for persona sign-off ─────────
    const fullName  = req.session.user.name || '';
    const userName  = fullName.split(' ')[0] || req.session.user.email?.split('@')[0] || 'Nami';

    let persona = req.body.persona;
    if (!nami.PERSONAS[persona]) persona = nami.personaOf((await getSettings(req.session.user.id).catch(() => ({}))).honeypot_persona);
    const reply     = await generateAIReply(emailBody || subject, subject, 0, [], userName, actualRecipient, persona, req.session.user.provider !== 'demo');
    const sessionId = `hp-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`;

    // ── CHANGE: Fix 3 — store the Re: subject in the session from the start ──
    // Every subsequent poll reply reads session.subject, so storing it WITH
    // the Re: prefix here means the subject never changes across the whole conversation.
    const replySubject = subject.startsWith('Re:') ? subject : `Re: ${subject}`;
    await sendReply(
      req.session.user,
      actualRecipient,
      replySubject,
      reply,
      {
        threadId:         threadId   || null,
        inReplyTo:        gmailMessageId || null,
        references:       gmailMessageId || null,
        replyToMessageId: emailId || null   // Outlook replies inside the original conversation
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
    await updateHoneypotSession(sessionId, { persona });
    await logUserActivity(req.session.user.id, 'Engaged Nami', `${subject} — ${actualRecipient} (${nami.PERSONAS[persona].label})`);

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

    teamAlerts.honeypot({ userId: req.session.user.id, senderEmail: actualRecipient, subject });

    res.json({ success: true, session: { ...session, persona }, replySent: reply });
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
      status:      s.status,
      persona:     s.persona || 'teacher',
      personaLabel: (nami.PERSONAS[s.persona] || nami.PERSONAS.teacher).label,
      stopReason:  s.stop_reason || null
    };
  });

  const totalMinutesWasted  = enriched.reduce((a, s) => a + s.minutesWasted, 0);
  const activeConversations = sessions.filter(s => s.status === 'active').length;
  const scammersDetected    = sessions.length; // every session = one scammer caught

  const monthStart = new Date(); monthStart.setDate(1); monthStart.setHours(0, 0, 0, 0);
  const leaderboard = {
    monthMinutes: enriched.filter(x => new Date(x.startedAt) >= monthStart).reduce((a, x) => a + x.minutesWasted, 0),
    longest:      [...enriched].sort((a, b) => b.minutesWasted - a.minutesWasted).slice(0, 5),
    mostReplies:  enriched.reduce((m, x) => Math.max(m, x.repliesSent || 0), 0)
  };

  res.json({
    success: true,
    leaderboard,
    personas: Object.fromEntries(Object.entries(nami.PERSONAS).map(([k, v]) => [k, v.label])),
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

      // Ask the user's mail provider (Gmail, Outlook or IMAP) for the newest
      // genuine reply from the scammer after our last reply + buffer.
      // Our own sent replies and anything already processed are ignored.
      const latestScammerMsg = await findLatestFrom(req.session.user, session.sender_email, {
        afterMs: cutoffTime,
        skipId:  session.last_processed_msg_id || null
      });

      if (!latestScammerMsg) {
        pollLock.delete(session.session_id);
        continue; // no genuine new reply from scammer yet
      }

      // Body of the scammer's reply (first 600 chars) for AI context
      const scammerText = latestScammerMsg.text || '';

      // ── Safety stop: end instead of replying ──────────────────
      const ageDays = (Date.now() - new Date(session.started_at).getTime()) / 86400000;
      const stopWhy = nami.safetyCheck(scammerText)
        || (session.replies_sent >= nami.MAX_REPLIES ? `Reached ${nami.MAX_REPLIES} replies` : null)
        || (ageDays >= nami.MAX_DAYS ? `Running for over ${nami.MAX_DAYS} days` : null);
      if (stopWhy) {
        try {
          await saveHoneypotMessage({ sessionId: session.session_id, direction: 'inbound', fromAddress: session.sender_email, body: scammerText, gmailMsgId: latestScammerMsg.id });
        } catch (_) {}
        await updateHoneypotSession(session.session_id, { last_processed_msg_id: latestScammerMsg.id });
        await endHoneypotSession(session.session_id, stopWhy);
        await logUserActivity(req.session.user.id, 'Nami stopped a conversation', `${stopWhy} — ${session.sender_email}`);
        results.push({ sessionId: session.session_id, scammer: session.sender_email, stopped: true, reason: stopWhy });
        console.log(`[Honeypot] Safety stop for ${session.sender_email}: ${stopWhy}`);
        continue;
      }

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
      const nextReply  = await generateAIReply(scammerText, session.subject, session.replies_sent, conversationHistory, pollUserName, session.sender_email, session.persona || nami.DEFAULT_PERSONA, req.session.user.provider !== 'demo');
      // ── CHANGE: subject already stored with Re: in session — use it directly, no recalculation ──
      const newSubject = session.subject;

      // The scammer's latest Message-ID for In-Reply-To threading
      const latestMsgId = latestScammerMsg.messageId || '';

      // Build growing References chain (tracks full conversation thread)
      const prevRefs     = session.references_hdr || session.message_id || '';
      const newRefs      = prevRefs ? `${prevRefs} ${latestMsgId}`.trim() : latestMsgId;

      await sendReply(
        req.session.user,
        session.sender_email,
        newSubject,
        nextReply,
        {
          threadId:         session.thread_id,
          inReplyTo:        latestMsgId || session.message_id,
          references:       newRefs,
          replyToMessageId: latestScammerMsg.id
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
      teamAlerts.honeypot({ userId: req.session.user.id, senderEmail: session.sender_email, subject: `[Reply #${session.replies_sent + 1}] ${session.subject}` });

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

  await endHoneypotSession(req.params.sessionId, 'Ended by you');
  if (target) await updateHoneypotSession(req.params.sessionId, { stop_reason: 'Ended by you' });
  await logUserActivity(req.session.user.id, 'Ended a Nami conversation', target ? target.sender_email : '');
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
