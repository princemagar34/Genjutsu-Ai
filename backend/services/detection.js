// ============================================================
// services/detection.js — extra detection layers (10–15),
// trust signals, MITRE ATT&CK tags and IOC extraction.
// ------------------------------------------------------------
// Used by threatService.analyseEmail. Every check returns plain
// data so it can be unit-tested without a mailbox.
// ============================================================
const { domainToUnicode } = require('url');

// ── HTML helpers (also used by the mail providers) ───────────
const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', '#39': "'" };
function decodeEntities(s) {
  return String(s || '')
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCodePoint(parseInt(n, 16)))
    .replace(/&([a-z#0-9]+);/gi, (m, n) => ENTITIES[n.toLowerCase()] ?? m);
}

function htmlToText(html) {
  if (!html) return '';
  return decodeEntities(String(html)
    .replace(/<(script|style|head)[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|tr|li|h[1-6]|table|section|article)>/gi, '\n')
    .replace(/<[^>]+>/g, ' '))
    .replace(/[ \t ]+/g, ' ')
    .replace(/ *\n */g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function anchorsFromHtml(html) {
  const out = [];
  if (!html) return out;
  const re = /<a\b[^>]*?href\s*=\s*(["'])(.*?)\1[^>]*>([\s\S]*?)<\/a>/gi;
  let m;
  while ((m = re.exec(html)) && out.length < 200) {
    out.push({ href: decodeEntities(m[2]).trim(), text: htmlToText(m[3]).replace(/\s+/g, ' ').trim() });
  }
  return out;
}

const linksFromHtml = (html) => anchorsFromHtml(html).map(a => a.href).filter(h => /^https?:\/\//i.test(h));

// ── Domain helpers ───────────────────────────────────────────
const SECOND_LEVEL = new Set(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.in', 'co.jp', 'co.nz',
  'com.np', 'edu.np', 'org.np', 'gov.np', 'net.np', 'mil.np', 'com.br', 'com.cn', 'co.za', 'com.sg', 'com.my', 'com.pk', 'com.bd']);

function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase().replace(/\.$/, ''); } catch (_) { return ''; }
}
function registrable(host) {
  const h = String(host || '').toLowerCase().replace(/^www\./, '');
  const parts = h.split('.').filter(Boolean);
  if (parts.length <= 2) return parts.join('.');
  const last2 = parts.slice(-2).join('.');
  return SECOND_LEVEL.has(last2) ? parts.slice(-3).join('.') : last2;
}
function sldOf(domain) {          // "paypal" from "paypal.com", "nabilbank" from "nabilbank.com.np"
  const reg = registrable(domain);
  return reg.split('.')[0] || '';
}
function addressOf(value) {
  const m = String(value || '').match(/<([^>]+)>/) || String(value || '').match(/([^\s<>"]+@[^\s<>"]+)/);
  return m ? m[1].trim().toLowerCase() : '';
}
function displayNameOf(value) {
  const s = String(value || '');
  return s.includes('<') ? s.slice(0, s.indexOf('<')).replace(/["']/g, '').trim() : '';
}
const domainOfAddress = (addr) => (String(addr).split('@')[1] || '').toLowerCase();

const FREE_MAIL = new Set(['gmail.com', 'googlemail.com', 'yahoo.com', 'ymail.com', 'hotmail.com', 'outlook.com', 'live.com',
  'msn.com', 'aol.com', 'icloud.com', 'me.com', 'proton.me', 'protonmail.com', 'gmx.com', 'gmx.net', 'yandex.com',
  'mail.com', 'zoho.com', 'rediffmail.com', 'qq.com', '163.com']);

// Brands people get impersonated as — with every domain the real brand sends from or links to
const BRANDS = {
  paypal:    ['paypal.com', 'paypal.me', 'paypalobjects.com', 'paypal-community.com'],
  google:    ['google.com', 'gmail.com', 'googlemail.com', 'youtube.com', 'googleusercontent.com', 'googleapis.com', 'gstatic.com', 'goo.gl', 'withgoogle.com', 'google.com.np', 'google-analytics.com', 'googletagmanager.com', 'googleadservices.com', 'googlesyndication.com', 'doubleclick.net', 'googleblog.com', 'g.co', 'blog.google', 'ggpht.com'],
  microsoft: ['microsoft.com', 'outlook.com', 'live.com', 'office.com', 'office365.com', 'microsoftonline.com', 'sharepoint.com', 'msn.com', 'azure.com', 'windows.net', 'onmicrosoft.com', 'bing.com', 'skype.com', 'xbox.com'],
  apple:     ['apple.com', 'icloud.com', 'me.com', 'mzstatic.com', 'apple.news'],
  amazon:    ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazonaws.com', 'amazonses.com', 'a2z.com', 'primevideo.com', 'amazon-adsystem.com', 'media-amazon.com', 'ssl-images-amazon.com'],
  netflix:   ['netflix.com', 'nflxext.com', 'nflximg.net'],
  facebook:  ['facebook.com', 'facebookmail.com', 'fb.com', 'fbcdn.net', 'meta.com'],
  instagram: ['instagram.com', 'cdninstagram.com', 'facebookmail.com'],
  whatsapp:  ['whatsapp.com', 'whatsapp.net'],
  linkedin:  ['linkedin.com', 'licdn.com'],
  dropbox:   ['dropbox.com', 'dropboxmail.com'],
  docusign:  ['docusign.com', 'docusign.net'],
  dhl:       ['dhl.com', 'dhl.de'],
  fedex:     ['fedex.com'],
  coinbase:  ['coinbase.com'],
  binance:   ['binance.com'],
  daraz:     ['daraz.com.np', 'daraz.com'],
  esewa:     ['esewa.com.np'],
  khalti:    ['khalti.com'],
  fonepay:   ['fonepay.com'],
  imepay:    ['imepay.com.np'],
  nabil:     ['nabilbank.com'],
  nicasia:   ['nicasiabank.com'],
  ncell:     ['ncell.axiata.com', 'ncell.com.np'],
  ntc:       ['ntc.net.np', 'nepaltelecom.com.np']
};
const BRAND_DOMAINS = new Set(Object.values(BRANDS).flat());
const isBrandDomain = (domain, brand) => {
  const reg = registrable(domain);
  return (brand ? BRANDS[brand] : [...BRAND_DOMAINS]).some(d => reg === d || domain === d || domain.endsWith('.' + d));
};

// Email marketing / link-tracking services: links through these are normal in newsletters
const ESP = /(^|\.)(customer\.io|sendgrid\.net|list-manage\.com|mcsv\.net|mailchimp\.com|mandrillapp\.com|sparkpostmail\.com|hubspotlinks\.com|hs-sites\.com|hubspot\.com|mailgun\.org|awstrack\.me|amazonses\.com|substack\.com|beehiiv\.com|convertkit\.com|ck\.page|klaviyo\.com|ctctcdn\.com|constantcontact\.com|rs6\.net|mailjet\.com|sendinblue\.com|brevo\.com|postmarkapp\.com|branch\.io|app\.link|urldefense\.com|safelinks\.protection\.outlook\.com|linkedin\.com|mlsend\.com|sg\.\w+|cmail\d+\.com|createsend\d*\.com|exacttarget\.com|sfmc-content\.com|mktossl\.com|marketo\.com|pardot\.com|intercom-mail\.com|intercom\.io|zendesk\.com|freshdesk\.com)$/i;
const TRACKER_HOST = /^(click|clicks|links?|email|emails|e|em|track|trk|t|go|r|url\d*|mail|news|info|lnk|ablink|elink)\./i;

// ── Look-alike detection ─────────────────────────────────────
function foldHomoglyphs(s) {
  return String(s).toLowerCase()
    .replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/cl/g, 'd')
    .replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/4/g, 'a').replace(/5/g, 's').replace(/7/g, 't').replace(/\$/g, 's')
    .replace(/[іі]/g, 'i').replace(/[оο]/g, 'o').replace(/[аα]/g, 'a').replace(/[еε]/g, 'e').replace(/[рρ]/g, 'p').replace(/[сϲ]/g, 'c');
}
function editDistance(a, b) {
  if (Math.abs(a.length - b.length) > 2) return 9;
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) {
    d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
  }
  return d[a.length][b.length];
}
// Returns the brand a domain imitates, or null
function lookalikeBrand(domain) {
  if (!domain || isBrandDomain(domain)) return null;
  let unicode = domain;
  try { unicode = domainToUnicode(domain) || domain; } catch (_) {}
  const sld = sldOf(unicode);
  const folded = foldHomoglyphs(sld);
  const tokens = folded.split(/[-_.]/).filter(Boolean);
  for (const brand of Object.keys(BRANDS)) {
    if (folded === brand && sld !== brand) return { brand, how: 'look-alike characters' };            // paypa1, g00gle, rnicrosoft
    if (sld !== brand && brand.length >= 6 && sld[0] === brand[0] && editDistance(sld, brand) === 1) return { brand, how: 'one letter different' }; // paypall, amazom
    if (tokens.length > 1 && tokens.includes(brand)) return { brand, how: 'brand name inside another domain' }; // paypal-secure-login
    if (domain.startsWith('xn--') && folded.includes(brand)) return { brand, how: 'disguised international characters' };
  }
  return null;
}

// ── Domain age (RDAP, free, no key) ──────────────────────────
const ageCache = new Map();               // domain -> { days, at }
const AGE_TTL = 24 * 60 * 60 * 1000;
let inFlight = 0;
const queue = [];
const slot = () => new Promise(res => { if (inFlight < 6) { inFlight++; res(); } else queue.push(res); });
const release = () => { const next = queue.shift(); if (next) next(); else inFlight--; };

async function domainAgeDays(domain, fetchImpl = globalThis.fetch) {
  const d = registrable(domain);
  if (!d || !d.includes('.') || /\.np$/.test(d)) return null;   // .np has no public RDAP
  const hit = ageCache.get(d);
  if (hit && Date.now() - hit.at < AGE_TTL) return hit.days;
  await slot();
  try {
    const res = await fetchImpl(`https://rdap.org/domain/${encodeURIComponent(d)}`, {
      headers: { Accept: 'application/rdap+json' }, redirect: 'follow', signal: AbortSignal.timeout(3500)
    });
    if (!res.ok) { ageCache.set(d, { days: null, at: Date.now() }); return null; }
    const data = await res.json();
    const reg = (data.events || []).find(e => /registration/i.test(e.eventAction));
    const days = reg ? Math.floor((Date.now() - new Date(reg.eventDate).getTime()) / 86400000) : null;
    ageCache.set(d, { days, at: Date.now() });
    return days;
  } catch (_) {
    return null;                          // offline or slow: unknown, never a penalty
  } finally { release(); }
}

// ── The extra layers ─────────────────────────────────────────
const BEC_HARD = ['change of bank details', 'changed our bank', 'new bank account', 'update our banking', 'updated bank details',
  'bank details have changed', 'payment to the new account', 'are you available', 'are you at your desk', 'keep this confidential',
  'send me your whatsapp', 'send me your number', 'i need a favour', 'i need a favor', 'buy gift cards', 'purchase gift cards'];
const BEC_SOFT = ['wire transfer', 'urgent payment', 'overdue invoice', 'outstanding invoice', 'remit payment', 'gift card'];
const CREDENTIAL_PHRASES = ['verify your account', 'confirm your password', 'enter your credentials', 'reset your password now',
  'confirm your identity', 'login attempt', 'update your payment', 'unusual activity'];

/**
 * Runs layers 10–15. Returns { score, reasons, hard, flags, badUrls }.
 * ctx.fetch can be injected in tests.
 */
async function extraLayers(email, ctx = {}) {
  const reasons = [], flags = new Set(), badUrls = new Set();
  let score = 0, hard = false;
  const fromAddr   = addressOf(email.from);
  const fromDomain = domainOfAddress(fromAddr);
  const fromReg    = registrable(fromDomain);
  const name       = displayNameOf(email.from).toLowerCase();
  const text       = `${email.subject || ''}\n${email.body || ''}`.toLowerCase();

  // 10. Display-name spoofing: "PayPal" <random@other-domain>
  for (const brand of Object.keys(BRANDS)) {
    if (new RegExp(`\\b${brand}\\b`, 'i').test(name.replace(/\s+/g, '')) || new RegExp(`\\b${brand}\\b`, 'i').test(name)) {
      if (fromDomain && !isBrandDomain(fromDomain, brand)) {
        score += 30; hard = true; flags.add('impersonation');
        reasons.push(`Display-name spoofing: says "${displayNameOf(email.from)}" but sent from ${fromDomain}`);
      }
      break;
    }
  }

  // 11. Look-alike domains (sender and links)
  const lookSender = lookalikeBrand(fromDomain);
  if (lookSender) {
    score += 35; hard = true; flags.add('impersonation');
    reasons.push(`Look-alike sender domain: ${fromDomain} imitates ${lookSender.brand} (${lookSender.how})`);
  }
  const linkHosts = [...new Set((email.links || []).map(hostOf).filter(Boolean))];
  let lookLinks = 0;
  for (const host of linkHosts) {
    const la = lookalikeBrand(host);
    if (la && lookLinks < 2) {
      lookLinks++; score += 30; hard = true; flags.add('link');
      (email.links || []).filter(u => hostOf(u) === host).forEach(u => badUrls.add(u));
      reasons.push(`Look-alike link domain: ${host} imitates ${la.brand} (${la.how})`);
    }
  }

  // 12. Reply-To goes somewhere else
  const replyAddr = addressOf(email.replyTo);
  const replyDomain = domainOfAddress(replyAddr);
  if (replyAddr && replyDomain && registrable(replyDomain) !== fromReg) {
    if (FREE_MAIL.has(registrable(replyDomain)) && !FREE_MAIL.has(fromReg)) {
      score += 25; hard = true; flags.add('impersonation');
      reasons.push(`Reply-To mismatch: replies go to a free email address (${replyAddr})`);
    } else if (flags.has('impersonation')) {
      score += 10; reasons.push(`Reply-To mismatch: replies go to ${replyAddr}`);
    }
  }

  // 13. Hidden links: the visible text shows one site, the link goes to another
  const verified = isVerified(email);
  let hidden = 0;
  for (const a of anchorsFromHtml(email.html)) {
    const shown = (a.text.match(/(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[\/\s]|$)/i) || [])[1];
    const target = hostOf(a.href);
    if (!shown || !target || !/\.[a-z]{2,}$/i.test(shown)) continue;
    if (registrable(shown.toLowerCase()) === registrable(target)) continue;
    if (verified && (ESP.test(target) || TRACKER_HOST.test(target) || registrable(target) === fromReg)) continue; // newsletter click-tracking
    if (hidden++ >= 2) break;
    score += 30; hard = true; flags.add('link'); badUrls.add(a.href);
    reasons.push(`Hidden link: text shows ${shown} but the link goes to ${target}`);
  }

  // 14. Payment fraud / business email compromise wording
  const becHard = BEC_HARD.filter(p => text.includes(p));
  const becSoft = BEC_SOFT.filter(p => text.includes(p));
  if (becHard.length) {
    score += 25 + Math.min(15, (becHard.length - 1) * 10); hard = true; flags.add('bec');
    reasons.push(`Payment-fraud wording: "${becHard[0]}"`);
  } else if (becSoft.length && !isNewsletter(email)) {
    score += 10; flags.add('bec');
    reasons.push(`Payment request wording: "${becSoft[0]}"`);
  }
  if (CREDENTIAL_PHRASES.some(p => text.includes(p))) flags.add('credentials');

  // 15. Newly registered domains (sender + up to 3 link domains)
  if (ctx.domainAge !== false) {
    const candidates = [...new Set([fromReg, ...linkHosts.map(registrable)])]
      .filter(d => d && !FREE_MAIL.has(d) && !BRAND_DOMAINS.has(d) && !ESP.test(d))
      .slice(0, 4);
    const ages = await Promise.all(candidates.map(d => domainAgeDays(d, ctx.fetch)));
    candidates.forEach((d, i) => {
      const days = ages[i];
      if (days == null) return;
      if (days < 30) {
        score += 30; hard = true; flags.add(d === fromReg ? 'impersonation' : 'link');
        if (d !== fromReg) (email.links || []).filter(u => registrable(hostOf(u)) === d).forEach(u => badUrls.add(u));
        reasons.push(`New domain: ${d} was registered ${days} day${days === 1 ? '' : 's'} ago`);
      } else if (days < 180) {
        score += 8; reasons.push(`Young domain: ${d} is ${Math.round(days / 30)} months old`);
      }
    });
  }

  return { score, reasons, hard, flags, badUrls: [...badUrls] };
}

// ── Trust signals ────────────────────────────────────────────
function authResultsOf(email) {
  const h = `${email.authResults || ''} ${email.arcAuthResults || ''}`;
  const g = (re) => ((h.match(re) || [])[1] || '').toLowerCase();
  return { spf: g(/spf=(\w+)/i) || ((email.receivedSpf || '').match(/^(\w+)/) || [])[1]?.toLowerCase() || '', dkim: g(/dkim=(\w+)/i), dmarc: g(/dmarc=(\w+)/i) };
}
function isVerified(email) {
  const a = authResultsOf(email);
  return a.dmarc === 'pass' || (a.spf === 'pass' && a.dkim === 'pass');
}
function isNewsletter(email) {
  return isVerified(email) && !!(email.listUnsubscribe || email.listId);
}

// ── MITRE ATT&CK ─────────────────────────────────────────────
const MITRE = {
  'T1566.001': 'Spearphishing Attachment',
  'T1566.002': 'Spearphishing Link',
  'T1598':     'Phishing for Information',
  'T1656':     'Impersonation',
  'T1566':     'Phishing',
  'T1204.002': 'User Execution: Malicious File',
  'T1027':     'Obfuscated Files or Information'
};
function mitreFor({ flags, riskyAttachment, badLink, authFail, level, maliciousFile, hiddenInFile }) {
  if (level === 'safe') return [];
  const ids = [];
  if (riskyAttachment || maliciousFile) ids.push('T1566.001');
  if (maliciousFile) ids.push('T1204.002');
  if (hiddenInFile) ids.push('T1027');
  if (badLink || flags.has('link')) ids.push('T1566.002');
  if (flags.has('credentials')) ids.push('T1598');
  if (flags.has('impersonation') || flags.has('bec') || authFail) ids.push('T1656');
  if (!ids.length) ids.push('T1566');
  return [...new Set(ids)].map(id => ({ id, name: MITRE[id], url: `https://attack.mitre.org/techniques/${id.replace('.', '/')}/` }));
}

// ── Indicators of compromise ─────────────────────────────────
function iocsFor(email, { badUrls = [], riskyAttachments = [], level }) {
  if (level === 'safe') return null;
  const fromAddr = addressOf(email.from);
  const replyAddr = addressOf(email.replyTo);
  const urls = [...new Set(badUrls)];
  const ips = [...new Set((email.links || []).map(hostOf).filter(h => /^\d{1,3}(\.\d{1,3}){3}$/.test(h)))];
  (email.links || []).filter(u => ips.includes(hostOf(u))).forEach(u => urls.includes(u) || urls.push(u));
  const domains = [...new Set([
    ...(FREE_MAIL.has(registrable(domainOfAddress(fromAddr))) ? [] : [domainOfAddress(fromAddr)]),
    ...urls.map(hostOf).filter(h => h && !ips.includes(h))
  ].filter(Boolean))];
  return {
    emails: [...new Set([fromAddr, replyAddr].filter(Boolean))],
    domains, urls, ips,
    attachments: riskyAttachments,
    hashes: (email.fileFindings || []).filter(f => (f.findings || []).some(x => x.level === 'dangerous')).map(f => ({ file: f.filename, sha256: f.sha256 }))
  };
}

module.exports = {
  htmlToText, anchorsFromHtml, linksFromHtml, decodeEntities,
  hostOf, registrable, addressOf, displayNameOf,
  lookalikeBrand, domainAgeDays, extraLayers,
  authResultsOf, isVerified, isNewsletter, mitreFor, iocsFor,
  FREE_MAIL, BRANDS, _ageCache: ageCache
};
