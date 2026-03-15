// ============================================================
// services/threatService.js — Multi-layer + ML + NLP + SPF/DKIM
// ============================================================
const { classifyText, extractNLPFeatures } = require('./mlService');

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

// Layer 6: SPF/DKIM/DMARC simulation
// Checks for common signs that the sender domain fails authentication
function checkSenderAuthentication(email) {
  const issues  = [];
  let   penalty = 0;
  const from    = (email.from || '').toLowerCase();
  const domain  = (from.match(/@([\w.-]+)/) || [])[1] || '';

  // Typosquatted domains (e.g. paypa1.com, g00gle.com)
  const typoPatterns = [/paypa[l1]\.com/, /go+gle\.com/, /amaz[o0]n\.com/,
                        /micros[o0]ft\.com/, /app[l1]e\.com/, /faceb[o0]{2}k\.com/];
  if (typoPatterns.some(p => p.test(domain))) {
    penalty += 45;
    issues.push(`SPF: Likely spoofed domain "${domain}"`);
  }

  // Free provider sending as business
  if (FREE_DOMAINS.includes(domain) &&
      (email.subject || '').match(/bank|paypal|amazon|microsoft|apple|netflix/i)) {
    penalty += 30;
    issues.push(`DKIM: Business name in subject from free email provider`);
  }

  // Mismatch between display name and actual email
  const displayName = from.split('<')[0].trim().toLowerCase();
  if (displayName.includes('paypal') && !domain.includes('paypal')) {
    penalty += 40; issues.push('DMARC: Display name mismatch — sender impersonation detected');
  }
  if (displayName.includes('amazon') && !domain.includes('amazon')) {
    penalty += 40; issues.push('DMARC: Display name mismatch — sender impersonation detected');
  }
  if (displayName.includes('microsoft') && !domain.includes('microsoft')) {
    penalty += 40; issues.push('DMARC: Display name mismatch — sender impersonation detected');
  }

  return { penalty, issues };
}

function analyseEmail(email) {
  const reasons = [];
  let   score   = 0;
  const bodyLower    = ((email.body || '') + ' ' + (email.subject || '')).toLowerCase();
  const senderDomain = (email.from.match(/@([\w.-]+)/) || [])[1] || '';

  // Layer 1: Phishing keywords (rule-based)
  PHISHING_KEYWORDS.forEach(kw => {
    if (bodyLower.includes(kw)) { score += 20; reasons.push(`Phishing keyword: "${kw}"`); }
  });

  // Layer 2: Suspicious links
  (email.links || []).forEach(link => {
    SUSPICIOUS_DOMAINS.forEach(pat => {
      if (pat.test(link)) { score += 35; reasons.push(`Suspicious domain in link: ${link}`); }
    });
    if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}/.test(link)) {
      score += 40; reasons.push(`IP-address URL detected: ${link}`);
    }
  });

  // Layer 3: Urgency language
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

  // Layer 6: SPF/DKIM/DMARC
  const auth = checkSenderAuthentication(email);
  score += auth.penalty;
  reasons.push(...auth.issues);

  // Layer 7: Naive Bayes ML classification
  const mlText   = `${email.subject || ''} ${(email.body || '').substring(0, 500)}`;
  const mlResult = classifyText(mlText);
  if (mlResult.label === 'phishing' && mlResult.confidence > 0.6) {
    const mlBonus = Math.round(mlResult.confidence * 30);
    score += mlBonus;
    reasons.push(`ML Classifier: phishing detected (confidence ${(mlResult.confidence * 100).toFixed(0)}%)`);
  }

  // Layer 8: NLP analysis
  const nlp = extractNLPFeatures(bodyLower);
  if (nlp.hasUrgencyLanguage) {
    score += 8; reasons.push(`NLP: High urgency language density (${nlp.urgencyCount} markers)`);
  }
  if (nlp.repetitionRate > 0.4) {
    score += 5; reasons.push('NLP: High word repetition (typical of spam)');
  }

  const level = score >= 60 ? 'dangerous' : score >= 30 ? 'suspicious' : 'safe';

  return {
    emailId:   email.id,
    level,
    score:     Math.min(score, 100),
    reasons:   [...new Set(reasons)], // deduplicate
    mlResult,
    nlpFeatures: nlp,
    scannedAt: new Date().toISOString()
  };
}

function scanEmails(emails) {
  return emails.map(email => ({ ...email, threat: analyseEmail(email) }));
}

module.exports = { analyseEmail, scanEmails };
