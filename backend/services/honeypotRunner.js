// ============================================================
// services/honeypotRunner.js — keeps Nami's conversations going
// ------------------------------------------------------------
// Runs on the server every 2 minutes for every user with an active
// conversation, so Nami works even when nobody has Genjutsu open.
// (The page's own 30-second check calls runForUser too; a per-session
// lock stops the two from handling the same conversation at once.)
//
// Each conversation goes through two steps:
//  1. Look for a new message from the scammer. If there is one: log it,
//     count the scammer's effort, and — if no reply is already waiting —
//     draw a "lottery ticket": a random moment 15 min – 24 h after the
//     message arrived (nami.drawReplyTime). Safety rules can end it here.
//  2. If the ticket's time has come, write the reply (AI, reading the whole
//     conversation, so it answers everything the scammer sent meanwhile)
//     and send it in the same thread.
// ============================================================
const https = require('https');
const db    = require('../database/db');
const nami  = require('./nami');
const { sendReply, findLatestFrom } = require('./mail');
const teamAlerts = require('./teamAlerts');
const { groqRequestOptions } = require('./groqModel');

const TICK_MS = 2 * 60 * 1000;
const busy = new Set();   // session IDs being handled right now

// ── AI reply ─────────────────────────────────────────────────
// conversationHistory: [{ direction: 'inbound'|'outbound', body }]
async function generateAIReply(scammerMessage, subject, repliesSent, conversationHistory = [], userName = 'Nami', senderEmail = '', persona = nami.DEFAULT_PERSONA, allowAI = true) {
  const firstName = (userName.split(' ')[0] || userName);
  const fb = () => nami.fallbackReply(persona, repliesSent, firstName);
  if (!process.env.GROQ_API_KEY || !allowAI) return fb();
  const clean = (t) => nami.sanitiseReply(t) || fb();   // never send anything that looks like real data

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
        { role: 'system', content: nami.systemPrompt(persona, firstName, repliesSent) },
        { role: 'user',   content: userPrompt }
      ]
    });
    const req = https.request({
      hostname: 'api.groq.com', path: '/openai/v1/chat/completions', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${process.env.GROQ_API_KEY}`, 'Content-Length': Buffer.byteLength(payload) }
    }, res => {
      let raw = '';
      res.on('data', c => { raw += c; });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(raw);
          if (parsed.error) { console.error('[Honeypot] Groq error:', parsed.error.message); return resolve(fb()); }
          const text = parsed?.choices?.[0]?.message?.content;
          resolve(text ? clean(text) : fb());
        } catch { resolve(fb()); }
      });
    });
    req.on('error', () => resolve(fb()));
    req.setTimeout(20000, () => { req.destroy(); resolve(fb()); });
    req.write(payload);
    req.end();
  });
}

const firstNameOf = (user) => (user.name || '').split(' ')[0] || (user.email || '').split('@')[0] || 'Nami';
const isDemo = (user) => user.provider === 'demo';
const ms = (d) => (d ? new Date(d).getTime() : 0);

// ── Step 1: a new message from the scammer? ──────────────────
async function checkForScammerReply(user, s, result) {
  // The demo's pretend scammer answers on a timer, not to Nami's messages, so
  // in the demo only listen for them once Nami's reply has gone out
  if (isDemo(user) && s.reply_due_at) return s;
  // Only messages newer than the last one we logged and Nami's last reply
  const afterMs = Math.max(ms(s.last_scammer_at), ms(s.last_reply_at), ms(s.started_at));
  const msg = await findLatestFrom(user, s.sender_email, { afterMs, skipId: s.last_processed_msg_id || null });
  if (!msg || msg.id === s.last_processed_msg_id) return s;

  const arrivedMs = msg.timestamp || ms(msg.date) || Date.now();
  const text = msg.text || '';
  await db.saveHoneypotMessage({ sessionId: s.session_id, direction: 'inbound', fromAddress: s.sender_email, body: text, gmailMsgId: msg.id });

  const effort = {
    scammer_replies:  (s.scammer_replies || 0) + 1,
    scammer_words:    (s.scammer_words || 0) + nami.wordCount(text),
    minutes_wasted:   Math.round((s.minutes_wasted || 0) + nami.effortMinutes(text)),
    first_scammer_at: s.first_scammer_at || new Date(arrivedMs).toISOString(),
    last_scammer_at:  new Date(arrivedMs).toISOString(),
    last_processed_msg_id: msg.id,
    effort_counted: 1
  };

  // Safety stop: end instead of replying
  const ageDays = (Date.now() - ms(s.started_at)) / 86400000;
  const stopWhy = nami.safetyCheck(text)
    || ((s.replies_sent || 0) >= nami.MAX_REPLIES ? `Reached ${nami.MAX_REPLIES} replies` : null)
    || (ageDays >= nami.MAX_DAYS ? `Running for over ${nami.MAX_DAYS} days` : null);
  if (stopWhy) {
    await db.updateHoneypotSession(s.session_id, effort);
    await db.endHoneypotSession(s.session_id, stopWhy);
    await db.logUserActivity(s.user_id, 'Nami stopped a conversation', `${stopWhy} — ${s.sender_email}`);
    result.stopped.push({ sessionId: s.session_id, reason: stopWhy });
    return null;
  }

  // Draw the lottery ticket, unless a reply is already waiting (that reply
  // will answer this message too, since it reads the whole conversation)
  const update = { ...effort, pending_msg_id: msg.id, pending_msg_hdr: msg.messageId || null };
  if (!s.reply_due_at) update.reply_due_at = nami.drawReplyTime(arrivedMs, { demo: isDemo(user) }).toISOString();
  await db.updateHoneypotSession(s.session_id, update);
  result.received++;
  return { ...s, ...update };
}

// ── Step 2: is it time to reply? ─────────────────────────────
async function sendDueReply(user, s, result) {
  if (!s.reply_due_at || ms(s.reply_due_at) > Date.now()) return;

  const history = (await db.getHoneypotMessages(s.session_id)).map(m => ({ direction: m.direction, body: m.body }));
  const lastIn  = [...history].reverse().find(m => m.direction === 'inbound');
  const persona = s.persona || nami.DEFAULT_PERSONA;
  const reply   = await generateAIReply(lastIn?.body || s.subject, s.subject, s.replies_sent || 0, history,
                                        firstNameOf(user), s.sender_email, persona, !isDemo(user));

  const inReplyTo = s.pending_msg_hdr || s.message_id || null;
  const prevRefs  = s.references_hdr || s.message_id || '';
  const refs      = s.pending_msg_hdr && !prevRefs.includes(s.pending_msg_hdr) ? `${prevRefs} ${s.pending_msg_hdr}`.trim() : prevRefs;

  try {
    await sendReply(user, s.sender_email, s.subject, reply, {
      threadId: s.thread_id, inReplyTo, references: refs || null,
      replyToMessageId: s.pending_msg_id || s.email_id || null
    });
  } catch (err) {
    if (err.noReply) {   // never answer a no-reply address
      await db.endHoneypotSession(s.session_id, 'No real reply address');
      result.stopped.push({ sessionId: s.session_id, reason: 'No real reply address' });
      return;
    }
    throw err;   // try again on the next round
  }

  await db.saveHoneypotMessage({ sessionId: s.session_id, direction: 'outbound', fromAddress: user.email || null, body: reply, gmailMsgId: null });
  await db.updateHoneypotSession(s.session_id, {
    replies_sent: (s.replies_sent || 0) + 1, last_reply_at: new Date().toISOString(),
    references_hdr: refs || null, reply_due_at: null, pending_msg_id: null, pending_msg_hdr: null
  });
  result.replied++;
  console.log(`[Honeypot] Nami replied to ${s.sender_email} (reply #${(s.replies_sent || 0) + 1})`);
  teamAlerts.honeypot({ userId: s.user_id, senderEmail: s.sender_email, subject: `[Reply #${(s.replies_sent || 0) + 1}] ${s.subject}` });
}

// ── One user's conversations ─────────────────────────────────
async function runForUser(user, sessions) {
  const result = { checked: 0, received: 0, replied: 0, stopped: [] };
  for (const session of sessions) {
    if (session.status !== 'active' || busy.has(session.session_id)) continue;
    busy.add(session.session_id);
    result.checked++;
    try {
      // Re-read: another round may have changed it a moment ago
      let s = await db.getHoneypotSessionById(session.session_id);
      if (!s || s.status !== 'active') continue;
      s = await checkForScammerReply(user, s, result);
      if (s) await sendDueReply(user, s, result);
    } catch (err) {
      console.warn(`[Honeypot] Session ${session.session_id}:`, err.message);
    } finally {
      busy.delete(session.session_id);
    }
  }
  return result;
}

// ── Every user, from the server ──────────────────────────────
async function runAll() {
  if (!(await db.claimJob('honeypot-runner', TICK_MS))) return;   // the other server has this round
  const sessions = await db.getActiveHoneypotSessionsAll();
  const byUser = new Map();
  for (const s of sessions) (byUser.get(s.user_id) || byUser.set(s.user_id, []).get(s.user_id)).push(s);
  for (const [userId, list] of byUser) {
    try {
      const user = await db.getStoredUser(userId);
      if (!user) continue;
      await runForUser(user, list);
      try { await db.saveStoredTokens(userId, user); } catch (_) {}   // keep a refreshed mailbox token
    } catch (err) {
      console.warn(`[Honeypot] User ${userId}:`, err.message);
    }
  }
}

function startHoneypotRunner() {
  const tick = () => runAll().catch(err => console.warn('[Honeypot] Runner:', err.message));
  setTimeout(tick, 30 * 1000).unref();
  setInterval(tick, TICK_MS).unref();
}

module.exports = { generateAIReply, runForUser, runAll, startHoneypotRunner };
