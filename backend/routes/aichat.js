// ============================================================
// routes/aichat.js — AI Chat using FREE Google Gemini API
//
// Get free key at: https://aistudio.google.com/app/apikey
// Add to .env:     GEMINI_API_KEY=your_key_here
//
// POST /api/ai/chat       { message, context }
// POST /api/ai/summarise  { subject, from, body, threat }
// ============================================================
const express         = require('express');
const { requireAuth } = require('../middleware/authMiddleware');
const https           = require('https');

const router = express.Router();

// ── Call Groq (free, no billing required) ────────────────────
// Sign up free at console.groq.com — add GROQ_API_KEY to .env
async function callGroq(systemPrompt, userMessage) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      model: 'llama-3.3-70b-versatile',
      messages: [
        { role: 'system', content: systemPrompt || 'You are a helpful assistant.' },
        { role: 'user',   content: userMessage }
      ],
      max_tokens:  500,
      temperature: 0.7
    });

    const options = {
      hostname: 'api.groq.com',
      path:     '/openai/v1/chat/completions',
      method:   'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${process.env.GROQ_API_KEY || ''}`,
        'Content-Length': Buffer.byteLength(payload)
      }
    };

    const req = https.request(options, res => {
      let raw = '';
      res.on('data', c => { raw += c; });
      res.on('end', () => {
        try {
          const p = JSON.parse(raw);
          if (p.error) {
            console.error('Groq API error:', p.error.message);
            return reject(new Error(p.error.message || 'Groq API error'));
          }
          const text = p?.choices?.[0]?.message?.content;
          if (!text) return reject(new Error('Groq returned no text'));
          resolve(text.trim());
        } catch (e) {
          console.error('Groq parse error:', raw.substring(0, 300));
          reject(new Error('Failed to parse Groq response'));
        }
      });
    });

    req.on('error', err => { console.error('Groq HTTPS error:', err.message); reject(err); });
    req.write(payload);
    req.end();
  });
}

// ── Call Claude (fallback if Anthropic credits available) ─────
async function callClaude(systemPrompt, userMessage) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      model: 'claude-sonnet-4-5', max_tokens: 500,
      system: systemPrompt,
      messages: [{ role: 'user', content: userMessage }]
    });
    const options = {
      hostname: 'api.anthropic.com', path: '/v1/messages', method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'x-api-key': process.env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      }
    };
    const req = https.request(options, res => {
      let raw = '';
      res.on('data', c => { raw += c; });
      res.on('end', () => {
        try {
          const p = JSON.parse(raw);
          if (p.error) return reject(new Error(p.error.message));
          const text = p?.content?.[0]?.text;
          if (!text) return reject(new Error('No text in Claude response'));
          resolve(text.trim());
        } catch (e) { reject(new Error('Claude parse error')); }
      });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

// ── Pick whichever provider has a key ────────────────────────
async function callAI(system, message) {
  if (process.env.GROQ_API_KEY)      return callGroq(system, message);  // free, recommended
  if (process.env.ANTHROPIC_API_KEY) return callClaude(system, message);
  throw new Error('No AI key found. Add GROQ_API_KEY to .env — free at console.groq.com');
}

function hasKey() {
  return !!(process.env.GROQ_API_KEY || process.env.ANTHROPIC_API_KEY);
}

// ── POST /api/ai/chat ─────────────────────────────────────────
router.post('/ai/chat', requireAuth, async (req, res) => {
  const { message, context } = req.body;
  if (!message) return res.status(400).json({ success: false, error: 'Message required.' });

  if (!hasKey()) {
    return res.json({ success: true,
      reply: 'No AI key configured. Add GROQ_API_KEY to .env — free key at console.groq.com (no billing needed)' });
  }

  try {
    const system = `You are Genjutsu AI, a friendly email security assistant inside the Genjutsu Gmail Security System.
Help users understand email threats, phishing attacks, and how to stay safe online.
Be friendly, concise, practical. Keep responses under 150 words.
If asked something unrelated to email security, politely redirect.
User context: ${context || 'Regular Gmail user'}`;

    const reply = await callAI(system, message);
    res.json({ success: true, reply });
  } catch (err) {
    console.error('AI chat error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── POST /api/ai/summarise ────────────────────────────────────
router.post('/ai/summarise', requireAuth, async (req, res) => {
  const { subject, from, body, threat } = req.body;
  if (!subject && !from) return res.status(400).json({ success: false, error: 'Email data required.' });

  if (!hasKey()) {
    return res.json({ success: true, summary: 'No AI key configured. Add GROQ_API_KEY to .env — free at console.groq.com' });
  }

  try {
    const system = `You are Genjutsu, an email security AI. Analyse emails for non-technical users.
Always use this format:
1. What this email is about (1-2 sentences)
2. Is it safe or dangerous and why (1-2 sentences)
3. What the user should do (1 sentence)
Under 120 words. No jargon.`;

    const prompt = `Analyse this email:
Subject: ${subject || 'No subject'}
From: ${from || 'Unknown'}
Preview: ${(body || '').substring(0, 400)}
Threat Score: ${threat?.score || 0}/100
Threat Level: ${threat?.level || 'unknown'}
Reasons: ${(threat?.reasons || []).slice(0, 3).join(', ') || 'none'}`;

    const summary = await callAI(system, prompt);
    res.json({ success: true, summary });
  } catch (err) {
    console.error('AI summarise error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
