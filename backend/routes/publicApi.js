// ============================================================
// routes/publicApi.js — /api/v1, for other tools (SIEM, scripts)
// Authenticate with:  Authorization: Bearer gj_xxxxxxxx
// ============================================================
const express = require('express');
const db = require('../database/db');
const { analyseEmail } = require('../services/threatService');
const siem = require('../services/siem');
const { rateLimit } = require('../middleware/rateLimit');

const router = express.Router();

async function apiKeyAuth(req, res, next) {
  const m = String(req.headers.authorization || '').match(/^Bearer\s+(\S+)$/i);
  const user = m ? await db.findUserByApiKey(m[1]).catch(() => null) : null;
  if (!user) return res.status(401).json({ success: false, error: 'Missing or invalid API key. Create one in Genjutsu → Settings → API keys.' });
  req.apiUser = user;
  next();
}
router.use(apiKeyAuth, rateLimit({ name: 'apikey', windowMs: 60 * 1000, max: 60, message: 'API limit: 60 requests a minute per key.' }));

const str = (v, max) => (typeof v === 'string' ? v.slice(0, max) : '');

// POST /api/v1/check — is this email safe?
router.post('/check', async (req, res) => {
  const b = req.body || {};
  if (!b.from && !b.subject && !b.body) return res.status(400).json({ success: false, error: 'Send at least one of: from, subject, body.' });
  const email = {
    id: 'api-' + Date.now(),
    from: str(b.from, 500), replyTo: str(b.replyTo, 500) || null, subject: str(b.subject, 1000),
    body: str(b.body, 50000), html: str(b.html, 200000),
    links: Array.isArray(b.links) ? b.links.filter(l => typeof l === 'string').slice(0, 100) : [],
    attachments: Array.isArray(b.attachments) ? b.attachments.slice(0, 20).map(a => ({ filename: str(a && a.filename, 255) })) : [],
    authResults: str(b.authResults, 2000), listUnsubscribe: str(b.listUnsubscribe, 1000) || null
  };
  if (!email.links.length) email.links = [...(email.body.matchAll(/https?:\/\/[^\s<>")\]]+/g))].map(x => x[0]).slice(0, 100);
  try {
    const ctx = await db.getScanContext(req.apiUser.id);
    const r = await analyseEmail(email, ctx);
    res.json({ success: true, result: { level: r.level, score: r.score, category: r.category || null, type: r.subType || null, reasons: r.reasons, mitre: r.mitre || [], iocs: r.iocs || null } });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// GET /api/v1/threats?days=30 — recent flagged emails
router.get('/threats', async (req, res) => {
  try {
    const days = Math.min(Math.max(parseInt(req.query.days) || 30, 1), 365);
    const { threats } = await db.getSiemRows(req.apiUser.id, days);
    const events = siem.toEvents(req.apiUser, threats, []);
    res.json({ success: true, count: events.length, threats: events });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// GET /api/v1/events?format=jsonl|cef|syslog&days=1 — for a SIEM to pull
router.get('/events', async (req, res) => {
  try {
    const days = Math.min(Math.max(parseInt(req.query.days) || 1, 1), 365);
    const { threats, activity } = await db.getSiemRows(req.apiUser.id, days);
    const out = siem.render(siem.toEvents(req.apiUser, threats, activity), String(req.query.format || 'jsonl'));
    res.type(out.type).send(out.body);
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

module.exports = router;
