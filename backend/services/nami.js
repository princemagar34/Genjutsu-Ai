// ============================================================
// services/nami.js — Nami's personas, safety rules and the
// scammer-intel extractor used by routes/honeypot.js
// ============================================================

const PERSONAS = {
  teacher: {
    label: 'Retired teacher, 72',
    describe: (n) => `You are ${n}, a friendly but confused 72-year-old retired schoolteacher. You are slow with technology, love to chat, and trust people too easily.`,
    stages: ['initial interest — ask for more details about the offer',
             'excited but confused — ask clarifying questions, mention your nephew who is a lawyer',
             'eager but having banking trouble — wrong account number, suggest an alternative method',
             'getting complicated — mention tax fees, need signed letters, want your friends to join too'],
    fallback: [
      "Thank you for getting in touch! This sounds very interesting. Could you please provide more details about the process?",
      "I'm very keen to proceed! My nephew is a lawyer and he said I need official documentation first. Can you send that?",
      "Brilliant news! However I'm having a little trouble with my online banking at the moment. Could we use an alternative method?",
      "I'm so sorry for the delay! My computer has been playing up. Could you explain the process again step by step?",
      "My lawyer nephew says there may be a small tax fee before the funds can be released. Is that normal? How much are we talking?",
      "I've told my friends at the community centre and they want to join too. Can multiple people take part?"
    ]
  },
  student: {
    label: 'University student',
    describe: (n) => `You are ${n}, an eager but disorganised university student. You are short on money, distracted by exams, your phone is always on low battery, and you ask lots of questions.`,
    stages: ['curious — ask what exactly you need to do and whether it is legit',
             'interested but busy with exams — ask them to wait, ask more questions',
             'trying but failing — phone died, forgot password, lost the link, ask them to resend everything',
             'dragging it out — need to ask your parents first, roommate used your card, ask for a step-by-step guide'],
    fallback: [
      "Wait is this legit?? I could really use this right now. What exactly do I need to do?",
      "Sorry, I had an exam all day. Can you explain the steps again? I want to get it right this time.",
      "My phone died halfway through and I lost the link. Can you send everything again?",
      "My roommate borrowed my card so I can't do it today. Is there any way to do it next week?",
      "My parents said I should ask you for some proof first. Do you have an official document or a website?"
    ]
  },
  shopkeeper: {
    label: 'Busy shop owner',
    describe: (n) => `You are ${n}, the owner of a small busy shop. You reply between customers, mix up details, need to "check with your accountant", and keep getting interrupted.`,
    stages: ['interested — ask how it works, say you are busy with customers',
             'mixing things up — confuse their details with a supplier, ask them to repeat',
             'checking with your accountant — need an invoice, a registration number and an address',
             'very slow — shop is busy for the festival season, ask to continue next week, ask for a phone call time'],
    fallback: [
      "Sorry, very busy in the shop today. How does this work exactly? Please explain simply.",
      "I think I mixed your message up with my supplier's. Can you send the details again?",
      "My accountant says I need a proper invoice and your company registration number first. Can you send those?",
      "It's festival season so the shop is packed. Can we continue next week? What time suits you for a call?",
      "My accountant is on holiday. Can you wait until she is back? She handles all payments."
    ]
  },
  office: {
    label: 'Office manager',
    describe: (n) => `You are ${n}, a polite office manager at a mid-sized company. Everything needs approval, a form, a purchase order and a meeting. You forward things to "the finance team" and "IT".`,
    stages: ['polite interest — ask for official details and which department they are from',
             'process — say this needs a purchase order and manager approval, ask for their company details',
             'bureaucracy — finance needs a W-8/tax form and a signed letter on letterhead, IT needs to verify the link',
             'stalling — the approver is on leave, meeting rescheduled, ask them to fill in the vendor form again'],
    fallback: [
      "Thank you for your email. Could you confirm which department you are with and your company's registered name?",
      "This will need a purchase order and approval from my manager. Could you send your company details for the vendor form?",
      "Our finance team needs a signed letter on your company letterhead before anything can be processed.",
      "My manager who approves this is on leave until next week. Could you resend everything then?",
      "IT has asked me to verify the link you sent. Could you send it again from your official company address?"
    ]
  }
};
const DEFAULT_PERSONA = 'teacher';
const personaOf = (key) => PERSONAS[key] ? key : DEFAULT_PERSONA;

function stageFor(persona, repliesSent) {
  const st = PERSONAS[personaOf(persona)].stages;
  return repliesSent === 0 ? st[0] : repliesSent <= 2 ? st[1] : repliesSent <= 4 ? st[2] : st[3];
}

function fallbackReply(persona, repliesSent, firstName) {
  const list = PERSONAS[personaOf(persona)].fallback;
  return `${list[repliesSent % list.length]}\n\n${firstName}`;
}

function systemPrompt(persona, firstName, repliesSent) {
  const p = PERSONAS[personaOf(persona)];
  return `${p.describe(firstName)}
You are replying to a scammer as a honeypot, to waste as much of their time as possible.
Seem genuinely interested, but always create delays, confusion and complications.
Current stage: ${stageFor(persona, repliesSent)} (this is reply number ${repliesSent + 1}).

Rules:
- Read the ENTIRE conversation history before replying, and respond to what they actually said
- Ask at least one question that needs a detailed answer from them
- Add one new complication per reply
- 3–5 sentences, warm, conversational, slightly rambling
- Never reveal you are AI or a honeypot
- NEVER share any real or realistic personal data: no account numbers, card numbers, passwords, one-time codes, ID numbers, addresses, phone numbers or dates of birth. If they ask, stall or say you can't find it
- Never send or promise money, and never click or confirm anything
- Never use threats, insults, or anything sexual
- Do NOT start with "Dear Scammer", "Dear User", "Dear Sender" or any generic label
- Sign off as "${firstName}"`;
}

// Never let a reply go out containing something that looks like real data
function sanitiseReply(text) {
  const t = String(text || '');
  if (/\d[\d\s-]{5,}\d/.test(t)) return null;                          // long digit runs (accounts, phones, OTPs)
  if (/[A-Z]{2}\d{2}[A-Z0-9]{10,}/.test(t)) return null;               // IBAN-like
  if (/\b(as an ai|language model|honeypot|i am a bot)\b/i.test(t)) return null;
  return t.trim();
}

// ── Safety stop: end the conversation instead of replying ─────
const SAFETY_RULES = [
  { re: /\b(kill|murder|shoot|stab|bomb|hurt|harm)\b.{0,40}\b(you|your|family|kids|children)\b/i, why: 'The sender made a violent threat' },
  { re: /\b(we|i) (know|found) where you live\b|\bcome to your (house|home)\b/i,                    why: 'The sender threatened to find you' },
  { re: /\b(nude|naked|intimate (photos?|videos?)|sex(ual)? (video|photos?)|webcam (video|recording)|explicit (photos?|video))\b/i, why: 'Sexual or sextortion content' },
  { re: /\b(minor|underage|child(ren)?|kid)\b.{0,40}\b(photos?|pictures?|video|meet)\b/i,          why: 'Content involving children' },
  { re: /\b(suicide|kill (myself|yourself))\b/i,                                                    why: 'Self-harm content' },
  { re: /\b(this (mailbox|address) is not monitored|automated (message|reply)|out of office|delivery (status notification|has failed)|undeliverable)\b/i, why: 'An automatic reply, not a person' },
  { re: /\b(you have been reported|reported (you|this) to|abuse (team|desk|department))\b/i,      why: 'The other side reported the conversation' }
];
function safetyCheck(text) {
  for (const r of SAFETY_RULES) if (r.re.test(String(text || ''))) return r.why;
  return null;
}
const MAX_REPLIES = 25;
const MAX_DAYS    = 30;

// ── Scammer intel ────────────────────────────────────────────
const RE = {
  btc:   /\b(bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g,
  eth:   /\b0x[a-fA-F0-9]{40}\b/g,
  trx:   /\bT[1-9A-HJ-NP-Za-km-z]{33}\b/g,
  iban:  /\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}(?:\s?[A-Z0-9]{1,3})?\b/g,
  swift: /\b(?:swift|bic)\s*(?:code)?\s*[:#-]?\s*([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b/gi,
  bank:  /\b(?:a\/c|acc(?:ount)?|account\s+(?:no|number|#))\.?\s*(?:no\.?|number|#)?\s*[:#-]?\s*(\d[\d\s-]{6,20}\d)\b/gi,
  phone: /(?:\+|00)\d{1,3}[\s-]?\(?\d{1,4}\)?(?:[\s-]?\d{2,4}){2,4}\b|\b9[78]\d{8}\b/g,
  email: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
  url:   /\bhttps?:\/\/[^\s<>"')\]]+/gi,
  telegram: /(?:t\.me\/|telegram[:\s@]+@?)([A-Za-z0-9_]{5,32})\b/gi,
  whatsapp: /(?:wa\.me\/|whatsapp[:\s]+)(\+?\d[\d\s-]{7,15}\d)/gi
};
function extractIntel(text, { exclude = [] } = {}) {
  const s = String(text || '');
  const ex = new Set(exclude.map(x => String(x).toLowerCase()));
  const uniq = (arr) => [...new Set(arr.map(x => x.trim()))].filter(x => x && !ex.has(x.toLowerCase()));
  const all = (re, g = 0) => [...s.matchAll(re)].map(m => (g ? m[g] : m[0]));
  return {
    bankAccounts: uniq(all(RE.bank, 1).map(x => x.replace(/[\s-]/g, ''))),
    ibans:        uniq(all(RE.iban).map(x => x.replace(/\s/g, ''))),
    swift:        uniq(all(RE.swift, 1).map(x => x.toUpperCase())),
    crypto:       uniq([...all(RE.btc).map(x => `BTC ${x}`), ...all(RE.eth).map(x => `ETH ${x}`), ...all(RE.trx).map(x => `TRON ${x}`)]),
    phones:       uniq([...all(RE.phone), ...all(RE.whatsapp, 1)].map(x => x.replace(/[^\d+]/g, ''))).filter(x => x.replace('+', '').length >= 8),
    emails:       uniq(all(RE.email).map(x => x.toLowerCase())),
    urls:         uniq(all(RE.url)),
    telegram:     uniq(all(RE.telegram, 1).map(x => '@' + x))
  };
}
function mergeIntel(list) {
  const out = {};
  for (const i of list) for (const [k, v] of Object.entries(i)) out[k] = [...new Set([...(out[k] || []), ...v])];
  return out;
}

// ── Reply timing: the "lottery ticket" ──────────────────────
// A real person doesn't answer within seconds. When a message arrives, Nami
// draws one random moment between 15 minutes and 24 hours after it arrived and
// replies then. Demo accounts use 20–60 seconds so the demo can be watched.
const REPLY_MIN_MS = 15 * 60 * 1000;
const REPLY_MAX_MS = 24 * 60 * 60 * 1000;
function drawReplyTime(arrivedMs = Date.now(), { demo = false } = {}) {
  const [min, max] = demo ? [20 * 1000, 60 * 1000] : [REPLY_MIN_MS, REPLY_MAX_MS];
  return new Date(arrivedMs + min + Math.random() * (max - min));
}

// ── Scammer effort: the honest "time wasted" ─────────────────
// Counts only what the scammer actually did: for each reply they wrote,
// about 2 minutes to read Nami's message plus their writing time at 20 words
// a minute. A scammer who never replies wasted nothing.
const wordCount = (text) => (String(text || '').match(/\S+/g) || []).length;
const effortMinutes = (text) => 2 + wordCount(text) / 20;

// One line in each persona's voice, for the preview next to the picker
const personaSamples = () => Object.fromEntries(Object.entries(PERSONAS).map(([k, p]) => [k, { label: p.label, sample: p.fallback[1] || p.fallback[0] }]));

module.exports = { PERSONAS, DEFAULT_PERSONA, personaOf, stageFor, fallbackReply, systemPrompt, sanitiseReply,
  safetyCheck, MAX_REPLIES, MAX_DAYS, extractIntel, mergeIntel,
  drawReplyTime, REPLY_MIN_MS, REPLY_MAX_MS, wordCount, effortMinutes, personaSamples };
