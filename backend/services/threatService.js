// ============================================================
// services/threatService.js — Multi-layer + ML + NLP + SPF/DKIM/DMARC
// ============================================================
const { classifyText, extractNLPFeatures } = require('./mlService');
const detection = require('./detection');
const { applyRules } = require('./rules');

const PHISHING_KEYWORDS = [
  'verify your account','confirm your password','unusual activity',
  'click here immediately','your account has been suspended',
  'update your payment','congratulations you won','limited time offer',
  'act now','urgent action required','free gift','claim your prize',
  'bank account details','wire transfer','enter your credentials',
  'reset your password now','your account will be closed',
  'confirm your identity','security alert','login attempt'
];

const SUSPICIOUS_DOMAINS = [
  /paypa1\.com/, /g00gle\.com/, /amaz0n\.com/, /micros0ft\.com/,
  /secure-login\./, /account-verify\./, /login-confirm\./, /verify-account\./
];

const FREE_DOMAINS = ['gmail.com','yahoo.com','hotmail.com','outlook.com','aol.com'];

// ── Layer 6: Real SPF/DKIM/DMARC header parsing ───────────────
// Gmail adds 'Authentication-Results' to every inbound message.
// We parse the actual pass/fail/none values from that header.
//
// Example header value:
//   mx.google.com;
//     dkim=pass header.i=@paypal.com;
//     spf=fail (google.com: domain does not designate ...) smtp.mailfrom=evil.com;
//     dmarc=fail (p=REJECT sp=REJECT dis=REJECT) header.from=paypal.com
//
function checkSenderAuthentication(email) {
  const issues  = [];
  let   penalty = 0;
  const from    = (email.from || '').toLowerCase();
  const domain  = (from.match(/@([\w.-]+)/) || [])[1] || '';

  // ── Parse real Authentication-Results header ──────────────
  const authHdr = (email.authResults || '') + ' ' + (email.arcAuthResults || '');
  const spfHdr  = email.receivedSpf || '';

  if (authHdr || spfHdr) {
    // SPF — extract result token after 'spf='
    const spfMatch = authHdr.match(/spf=(pass|fail|softfail|neutral|none|permerror|temperror)/i)
                  || spfHdr.match(/^(pass|fail|softfail|neutral|none)/i);
    const spfResult = spfMatch ? spfMatch[1].toLowerCase() : null;

    if (spfResult === 'fail' || spfResult === 'permerror') {
      penalty += 40;
      issues.push(`SPF: FAIL — sending server not authorised for domain "${domain}"`);
    } else if (spfResult === 'softfail') {
      penalty += 20;
      issues.push(`SPF: SOFTFAIL — sending server weakly unauthorised for domain "${domain}"`);
    } else if (spfResult === 'pass') {
      // SPF passed — small trust bonus (offset score slightly)
      penalty -= 5;
    }

    // DKIM — extract result token after 'dkim='
    const dkimMatch  = authHdr.match(/dkim=(pass|fail|neutral|none|permerror|temperror)/i);
    const dkimResult = dkimMatch ? dkimMatch[1].toLowerCase() : null;

    if (dkimResult === 'fail' || dkimResult === 'permerror') {
      penalty += 35;
      issues.push('DKIM: FAIL — email signature invalid or missing, message may be tampered');
    } else if (dkimResult === 'none') {
      penalty += 10;
      issues.push('DKIM: NONE — no digital signature present on this email');
    } else if (dkimResult === 'pass') {
      penalty -= 5;
    }

    // DMARC — extract result token after 'dmarc='
    const dmarcMatch  = authHdr.match(/dmarc=(pass|fail|none|quarantine|reject)/i);
    const dmarcResult = dmarcMatch ? dmarcMatch[1].toLowerCase() : null;

    if (dmarcResult === 'fail') {
      penalty += 45;
      issues.push('DMARC: FAIL — sender domain policy violated, likely spoofed identity');
    } else if (dmarcResult === 'none') {
      penalty += 5;
      issues.push('DMARC: NONE — domain has no DMARC policy (unprotected sender)');
    } else if (dmarcResult === 'pass') {
      penalty -= 5;
    }

    // DKIM domain alignment — check if signing domain matches From domain
    const dkimDomainMatch = authHdr.match(/dkim=pass\s+header\.i=@([\w.-]+)/i);
    if (dkimDomainMatch) {
      const signingDomain = dkimDomainMatch[1].toLowerCase();
      if (domain && !domain.endsWith(signingDomain) && !signingDomain.endsWith(domain)) {
        penalty += 25;
        issues.push(`DKIM: Domain mismatch — signed by "${signingDomain}" but From is "${domain}"`);
      }
    }
  } else {
    // No auth headers at all — fall back to pattern-based heuristics
    const typoPatterns = [/paypa[l1]\.com/, /go+gle\.com/, /amaz[o0]n\.com/,
                          /micros[o0]ft\.com/, /app[l1]e\.com/, /faceb[o0]{2}k\.com/];
    if (typoPatterns.some(p => p.test(domain))) {
      penalty += 45;
      issues.push(`SPF: Likely spoofed domain "${domain}" (typosquatting detected)`);
    }

    if (FREE_DOMAINS.includes(domain) &&
        (email.subject || '').match(/bank|paypal|amazon|microsoft|apple|netflix/i)) {
      penalty += 30;
      issues.push('DKIM: Business name in subject sent from free email provider');
    }

    const displayName = from.split('<')[0].trim().toLowerCase();
    const brands      = ['paypal','amazon','microsoft','apple','google','netflix','hsbc','barclays'];
    brands.forEach(brand => {
      if (displayName.includes(brand) && !domain.includes(brand)) {
        penalty += 40;
        issues.push(`DMARC: Display name impersonation — claims to be "${brand}" but domain is "${domain}"`);
      }
    });
  }

  return { penalty: Math.max(penalty, 0), issues };
}

// ── Dangerous attachment extensions ──────────────────────────
const DANGEROUS_EXTENSIONS = [
  'exe','bat','cmd','com','msi','ps1','vbs','js','jse','wsf','wsh',  // executables/scripts
  'scr','pif','application','gadget','hta',                           // Windows-specific
  'jar','py','rb','pl',                                               // runtimes
  'zip','rar','7z','tar','gz','iso','img',                           // archives (often wrap malware)
  'doc','docm','xls','xlsm','ppt','pptm',                           // macro-enabled Office
  'html','htm','svg',                                                 // can contain scripts
  'lnk','url'                                                        // shortcut files
];

const SUSPICIOUS_EXTENSIONS = [
  'pdf',    // can contain embedded JS
  'docx','xlsx','pptx',  // modern Office (macros rare but possible)
  'rtf',    // can exploit Word parser
  'odt','ods'
];

// Double-extension pattern — e.g. "invoice.pdf.exe"
const DOUBLE_EXT_RE = /\.\w{2,4}\.(exe|bat|cmd|scr|vbs|js|pif|com)$/i;

function scanAttachments(email) {
  const attachments = email.attachments || [];
  if (attachments.length === 0) return { penalty: 0, issues: [], details: [] };

  let   penalty = 0;
  const issues  = [];
  const details = [];

  for (const att of attachments) {
    const name = (att.filename || '').toLowerCase();
    const ext  = name.split('.').pop() || '';
    const sizeMB = ((att.size || 0) / 1024 / 1024).toFixed(2);

    let risk = 'clean';

    if (DOUBLE_EXT_RE.test(name)) {
      penalty += 60;
      risk = 'dangerous';
      issues.push(`Attachment: double-extension disguise detected — "${att.filename}"`);
    } else if (DANGEROUS_EXTENSIONS.includes(ext)) {
      penalty += 40;
      risk = 'dangerous';
      issues.push(`Attachment: dangerous file type ".${ext}" — "${att.filename}"`);
    } else if (SUSPICIOUS_EXTENSIONS.includes(ext)) {
      penalty += 10;
      risk = 'suspicious';
      issues.push(`Attachment: potentially risky file type ".${ext}" — "${att.filename}"`);
    }

    // Flag very large attachments from unknown senders (>10MB) — unusual for phishing
    // but flag zero-byte attachments (can be used to trigger parser bugs)
    if (att.size === 0 && ext !== '') {
      penalty += 15;
      risk = risk === 'clean' ? 'suspicious' : risk;
      issues.push(`Attachment: zero-byte file — "${att.filename}" (possible parser exploit)`);
    }

    details.push({
      filename:  att.filename,
      mimeType:  att.mimeType,
      size:      att.size,
      sizeMB,
      extension: ext,
      risk
    });
  }

  return { penalty: Math.min(penalty, 80), issues, details };
}

const TRUSTED_DOMAINS = [
  'google.com', 'googlemail.com', 'accounts.google.com', 'mail.google.com',
  'microsoft.com', 'outlook.com', 'apple.com', 'amazon.com', 'amazon.co.uk',
  'paypal.com', 'linkedin.com', 'github.com', 'twitter.com', 'facebook.com',
  'netflix.com', 'spotify.com', 'dropbox.com', 'zoom.us', 'slack.com'
];

const SYSTEM_SENDERS = /mailer-daemon|postmaster|delivery.*subsystem|mail.*delivery/i;

// ── Google Safe Browsing API check ───────────────────────────
async function checkUrlsSafeBrowsing(urls) {
  if (!process.env.SAFE_BROWSING_API_KEY || urls.length === 0)
    return { penalty: 0, issues: [] };

  try {
    const https   = require('https');
    const payload = JSON.stringify({
      client: { clientId: 'genjutsu', clientVersion: '1.0' },
      threatInfo: {
        threatTypes:      ['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes:    ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries:    urls.map(u => ({ url: u }))
      }
    });

    return new Promise((resolve) => {
      const options = {
        hostname: 'safebrowsing.googleapis.com',
        path:     `/v4/threatMatches:find?key=${process.env.SAFE_BROWSING_API_KEY}`,
        method:   'POST',
        headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
      };

      const req = https.request(options, res => {
        let raw = '';
        res.on('data', c => { raw += c; });
        res.on('end', () => {
          try {
            const data    = JSON.parse(raw);
            const matches = data.matches || [];
            if (matches.length === 0) return resolve({ penalty: 0, issues: [] });
            const issues = matches.map(m =>
              `Safe Browsing: ${m.threatType} detected in URL: ${m.threat.url}`
            );
            resolve({ penalty: Math.min(matches.length * 50, 100), issues });
          } catch { resolve({ penalty: 0, issues: [] }); }
        });
      });
      req.on('error', () => resolve({ penalty: 0, issues: [] }));
      req.write(payload);
      req.end();
    });
  } catch { return { penalty: 0, issues: [] }; }
}

async function analyseEmail(email, ctx = {}) {
  const fromLower    = (email.from || '').toLowerCase();
  const senderDomain = (fromLower.match(/@([\w.-]+)/) || [])[1] || '';

  if (SYSTEM_SENDERS.test(fromLower)) {
    return { emailId: email.id, level: 'safe', subType: null, score: 0, category: 'system',
             reasons: ['System delivery notification'],
             mlResult: { label: 'safe', confidence: 0 },
             nlpFeatures: {}, authDetails: {}, mitre: [], iocs: null,
             scannedAt: new Date().toISOString() };
  }
  const result = await analyseEmailUncapped(email, ctx);
  // Well-known senders are capped low, but never when the email shows
  // real danger signs (forged sender, look-alike link, etc.)
  if (!result._hard && TRUSTED_DOMAINS.some(d => senderDomain === d || senderDomain.endsWith('.' + d))) {
    result.score = Math.min(result.score, 25);
    finalise(result);
  }
  delete result._hard;
  return result;
}

// Recompute level/subType/MITRE/IOCs after any score change
function finalise(r) {
  r.level = r.score >= 60 ? 'dangerous' : r.score >= 30 ? 'suspicious' : 'safe';
  if (r.level === 'safe') { r.subType = null; r.mitre = []; r.iocs = null; }
  return r;
}

async function analyseEmailUncapped(email, ctx = {}) {
  const reasons = [];
  let   score   = 0;
  const bodyLower    = ((email.body || '') + ' ' + (email.subject || '')).toLowerCase();
  const senderDomain = ((email.from || '').match(/@([\w.-]+)/) || [])[1] || '';

  // Layer 1: Phishing keywords
  PHISHING_KEYWORDS.forEach(kw => {
    if (bodyLower.includes(kw)) { score += 20; reasons.push(`Phishing keyword: "${kw}"`); }
  });

  // Layer 2: Suspicious link patterns (regex)
  (email.links || []).forEach(link => {
    SUSPICIOUS_DOMAINS.forEach(pat => {
      if (pat.test(link)) { score += 35; reasons.push(`Suspicious domain in link: ${link}`); }
    });
    if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}/.test(link)) {
      score += 40; reasons.push(`IP-address URL detected: ${link}`);
    }
  });
  ['urgent','immediately','expire','suspended','locked','warning','alert']
    .forEach(w => { if (bodyLower.includes(w)) { score += 10; reasons.push(`Urgency word: "${w}"`); } });

  // Layer 4: Sender domain check
  if (FREE_DOMAINS.includes(senderDomain) &&
      (email.subject || '').toLowerCase().match(/bank|paypal|verify/)) {
    score += 25; reasons.push('Bank/payment email from free email provider');
  }

  // Layer 5: High link count
  if ((email.links || []).length > 5) {
    score += 15; reasons.push(`High link count (${email.links.length})`);
  }

  // Layer 5b: Google Safe Browsing API — catches real phishing/malware URLs
  // ── CHANGE: track sbPenalty separately so subType logic can read it below ──
  let sbPenalty = 0;
  if ((email.links || []).length > 0) {
    const sbResult = await checkUrlsSafeBrowsing(email.links.slice(0, 10));
    sbPenalty = sbResult.penalty;
    score += sbPenalty;
    reasons.push(...sbResult.issues);
  }

  // Layer 6: Real SPF/DKIM/DMARC header parsing
  const auth = checkSenderAuthentication(email);
  score += auth.penalty;
  reasons.push(...auth.issues);

  // Layer 7: Naive Bayes ML
  const mlText   = `${email.subject || ''} ${(email.body || '').substring(0, 500)}`;
  const mlResult = classifyText(mlText);
  if (mlResult.label === 'phishing' && mlResult.confidence > 0.6) {
    const mlBonus = Math.round(mlResult.confidence * 30);
    score += mlBonus;
    reasons.push(`ML Classifier: phishing detected (confidence ${(mlResult.confidence * 100).toFixed(0)}%)`);
  }

  // Layer 8: NLP
  const nlp = extractNLPFeatures(bodyLower);
  if (nlp.hasUrgencyLanguage) {
    score += 8; reasons.push(`NLP: High urgency language density (${nlp.urgencyCount} markers)`);
  }
  if (nlp.repetitionRate > 0.4) {
    score += 5; reasons.push('NLP: High word repetition (typical of spam)');
  }

  // Layer 9: Attachment scanning
  const attScan = scanAttachments(email);
  score += attScan.penalty;
  reasons.push(...attScan.issues);

  // Layers 10–15: display-name spoofing, look-alike domains, Reply-To mismatch,
  // hidden links, payment-fraud wording, newly registered domains
  const extra = await detection.extraLayers(email, ctx);
  score += extra.score;
  reasons.push(...extra.reasons);

  // "Hard" signs are things legitimate senders don't do. Trust signals below
  // never cancel them out.
  const ipLink  = (email.links || []).some(l => /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}/.test(l));
  const regexLink = (email.links || []).some(l => SUSPICIOUS_DOMAINS.some(p => p.test(l)));
  const riskyAtt = (attScan.details || []).filter(d => d.risk === 'dangerous');
  // Layer 16: Genjutsu's global block list (domains an admin blocked for everyone)
  let globalBlock = null;
  if (ctx.blockedDomains && ctx.blockedDomains.size) {
    const senderDom = (detection.addressOf(email.from) || '').split('@')[1] || '';
    const doms = [senderDom, ...(email.links || []).map(l => detection.hostOf(l))]
      .filter(Boolean).map(d => detection.registrable(d.toLowerCase()));
    globalBlock = doms.find(d => ctx.blockedDomains.has(d)) || null;
    if (globalBlock) { score += 100; reasons.unshift(`On Genjutsu's global block list: ${globalBlock}`); }
  }
  // Layer 18: what's INSIDE the attachments (services/attachmentScanner.js ran before this)
  let fileDanger = [], fileWarn = [];
  for (const f of email.fileFindings || []) {
    for (const x of f.findings || []) {
      if (x.level === 'dangerous') fileDanger.push(`Dangerous file contents: "${f.filename}" ${x.text}`);
      else if (x.level === 'suspicious') fileWarn.push(`File contents: "${f.filename}" ${x.text}`);
    }
    for (const q of f.qr || []) reasons.push(/^https?:/i.test(q) ? `QR code in "${f.filename}" opens ${q.slice(0, 120)}` : `QR code in "${f.filename}" contains: ${q.slice(0, 80)}`);
  }
  if (fileDanger.length) { score += Math.min(70, 50 + 10 * (fileDanger.length - 1)); reasons.push(...fileDanger); }
  if (fileWarn.length) { score += Math.min(30, 15 * fileWarn.length); reasons.push(...fileWarn); }
  const qrLinks = (email.fileFindings || []).flatMap(f => f.qr || []).filter(q => /^https?:/i.test(q));
  if (qrLinks.length && /\b(scan|qr)\b/i.test(`${email.subject || ''} ${email.body || ''}`)) {
    score += 15; reasons.push('Asks you to scan a QR code: a common way to hide a scam link from email filters');
  }

  // Layer 17: the shared threat feed — attackers seen hitting several Genjutsu users
  let sharedHit = null;
  if (ctx.shared && (ctx.shared.domains?.size || ctx.shared.senders?.size)) {
    const addr = detection.addressOf(email.from) || '';
    const sDom = detection.registrable((addr.split('@')[1] || '').toLowerCase());
    const linkDoms = (email.links || []).map(l => detection.registrable(detection.hostOf(l))).filter(Boolean);
    if (ctx.shared.senders?.has(addr)) sharedHit = { value: addr, users: ctx.shared.senders.get(addr) };
    else for (const d of [sDom, ...linkDoms]) if (ctx.shared.domains?.has(d)) { sharedHit = { value: d, users: ctx.shared.domains.get(d) }; break; }
    if (sharedHit) { score += 45; reasons.unshift(`Seen in attacks on ${sharedHit.users} Genjutsu users: ${sharedHit.value}`); }
  }

  const hard = extra.hard || sbPenalty > 0 || auth.penalty >= 20 || ipLink || regexLink || riskyAtt.length > 0 || !!globalBlock || !!sharedHit || fileDanger.length > 0;

  // ── Trust signals (cut newsletter false alarms) ─────────────
  let category = null;
  const fromAddr = detection.addressOf(email.from);
  if (!hard) {
    if (detection.isNewsletter(email)) {
      category = 'newsletter';
      score = Math.min(score, 24);
      reasons.unshift('Verified newsletter: sender passed SPF/DKIM/DMARC and includes an unsubscribe option');
    }
    if (ctx.safeSenders && ctx.safeSenders.has(fromAddr)) {
      score = Math.min(score, 15);
      reasons.unshift('You marked this sender as safe');
    } else if (ctx.history && (ctx.history[fromAddr] || 0) >= 3) {
      score = Math.max(0, score - 10);
      reasons.push(`Known sender: ${ctx.history[fromAddr]} earlier emails were safe`);
    }
  }

  // ── Sender history: a first-time sender is a warning sign only together with others ──
  let senderHistory = null;
  if (ctx.seen) {
    const prev = ctx.seen[fromAddr];
    const earlier = prev ? Math.max(0, prev.n - (prev.ids.includes(email.id) ? 1 : 0)) : 0;
    senderHistory = { earlier, firstTime: earlier === 0, firstSeen: earlier ? prev.first : null };
    if (earlier === 0 && score >= 20 && !category) { score += 10; reasons.push('First email from this sender: you have never received mail from this address before'); }
  }

  // ── The user's own rules ─────────────────────────────────────
  // trust never overrides hard danger signs; flag/quarantine always apply
  const rule = applyRules(ctx.rules, email);
  let quarantineByRule = false;
  if (rule) {
    if (rule.action === 'trust' && !hard) { score = Math.min(score, 15); reasons.unshift(rule.text); }
    else if (rule.action === 'flag')       { score = Math.max(score, 30); reasons.unshift(rule.text); }
    else if (rule.action === 'quarantine') { score = Math.max(score, 60); reasons.unshift(rule.text); quarantineByRule = true; }
  }

  const level = score >= 60 ? 'dangerous' : score >= 30 ? 'suspicious' : 'safe';

  // ── CHANGE: Sub-type classification (post-analysis enrichment) ───────────
  // After all 9 layers run, we assign a sub-type label so the dashboard can
  // split threats across 4 cards (Phishing, Malware Links, Spoofed Senders, Other).
  // Priority order: malware_link > spoofed_sender > phishing > other
  // Safe emails get null — they never appear on the threat cards.
  // What kind of threat it is (one of the four Threat Analysis cards). Decided by what
  // the email is trying to do, most harmful first:
  //   malware_link   - a known-malicious link (Google Safe Browsing) or a dangerous file
  //   phishing       - a bad link to steal logins (look-alike, hidden, IP-address or
  //                    known-scam link, or a brand new domain), or login-stealing wording
  //   spoofed_sender - pretends to be someone without a bad link: fake display name,
  //                    failed SPF/DKIM/DMARC, Reply-To mismatch, change-of-bank-details
  //   other          - caught by other signals (wording, many links, the model)
  let subType = null;
  if (level !== 'safe') {
    const badLink = extra.flags.has('link') || ipLink || regexLink || !!globalBlock || !!sharedHit ||
      reasons.some(r => /^New domain:|^Suspicious URL|^IP-address URL/.test(r));
    if (sbPenalty > 0 || riskyAtt.length > 0 || fileDanger.length > 0) subType = 'malware_link';
    else if (badLink) subType = 'phishing';
    else if (extra.flags.has('impersonation') || extra.flags.has('bec') || auth.penalty > 0) subType = 'spoofed_sender';
    else if (extra.flags.has('credentials') || reasons.some(r => r.includes('Phishing keyword') || r.includes('ML Classifier'))) subType = 'phishing';
    else subType = 'other';
  }

  return {
    emailId:           email.id,
    level,
    subType,                          // ← NEW: 'phishing' | 'malware_link' | 'spoofed_sender' | 'other' | null
    score:             Math.min(score, 100),
    reasons:           [...new Set(reasons)],
    mlResult,
    nlpFeatures:       nlp,
    authDetails:       { raw: email.authResults || '', issues: auth.issues },
    attachmentDetails: attScan.details,
    category,                         // 'newsletter' | null
    quarantineByRule,
    mitre: detection.mitreFor({ flags: extra.flags, riskyAttachment: riskyAtt.length > 0, badLink: sbPenalty > 0 || ipLink || regexLink, authFail: auth.penalty >= 20, level,
      maliciousFile: fileDanger.length > 0, hiddenInFile: qrLinks.length > 0 || fileWarn.some(r => /password-locked|another archive/.test(r)) }),
    iocs:  detection.iocsFor(email, {
      level,
      badUrls: [...extra.badUrls, ...(email.links || []).filter(l => SUSPICIOUS_DOMAINS.some(p => p.test(l)) || /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}/.test(l)), ...(sbPenalty > 0 ? (email.links || []).slice(0, 10).filter(l => reasons.some(r => r.includes(l))) : [])],
      riskyAttachments: riskyAtt.map(d => d.filename)
    }),
    _hard: hard,
    senderHistory,
    sharedFeed: sharedHit,
    scannedAt:         new Date().toISOString()
  };
}

async function scanEmails(emails, ctx = {}) {
  return Promise.all(emails.map(email => analyseEmail(email, ctx)));
}

module.exports = { analyseEmail, scanEmails };
