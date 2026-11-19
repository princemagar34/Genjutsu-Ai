// ============================================================
// services/rules.js — the user's own rules
//   field:  sender (exact address) | domain (sender domain, incl. subdomains)
//           subject (contains) | attachment (file extension, e.g. "exe")
//   action: trust | flag | quarantine
// ============================================================
const { addressOf } = require('./detection');

const FIELDS  = ['sender', 'domain', 'subject', 'attachment'];
const ACTIONS = ['trust', 'flag', 'quarantine'];

function validateRule({ field, value, action }) {
  if (!FIELDS.includes(field))  return 'Choose what the rule checks';
  if (!ACTIONS.includes(action)) return 'Choose what the rule does';
  const v = String(value || '').trim().toLowerCase();
  if (!v || v.length > 200) return 'Enter a value for the rule';
  if (field === 'sender' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return 'Enter a full email address';
  if (field === 'domain' && !/^@?[a-z0-9.-]+\.[a-z]{2,}$/.test(v)) return 'Enter a domain like college.edu.np';
  if (field === 'attachment' && !/^\.?[a-z0-9]{1,10}$/.test(v)) return 'Enter a file type like exe or zip';
  return null;
}

function ruleMatches(rule, email) {
  const v = String(rule.value || '').toLowerCase().replace(/^@/, '').replace(/^\./, '');
  const from = addressOf(email.from);
  switch (rule.field) {
    case 'sender':     return from === v;
    case 'domain':     { const d = from.split('@')[1] || ''; return d === v || d.endsWith('.' + v); }
    case 'subject':    return String(email.subject || '').toLowerCase().includes(v);
    case 'attachment': return (email.attachments || []).some(a => String(a.filename || '').toLowerCase().endsWith('.' + v));
    default:           return false;
  }
}

const describe = (r) => ({
  sender: `sender is ${r.value}`, domain: `sender's domain is ${r.value.replace(/^@/, '')}`,
  subject: `subject contains "${r.value}"`, attachment: `has a .${r.value.replace(/^\./, '')} attachment`
}[r.field] || r.value);

// Strongest matching rule wins: quarantine > flag > trust
function applyRules(rules, email) {
  const hits = (rules || []).filter(r => ruleMatches(r, email));
  for (const action of ['quarantine', 'flag', 'trust']) {
    const r = hits.find(h => h.action === action);
    if (r) return { action, rule: r, text: `Your rule: ${describe(r)} → ${action === 'trust' ? 'trust' : action === 'flag' ? 'mark worth a look' : 'quarantine'}` };
  }
  return null;
}

module.exports = { FIELDS, ACTIONS, validateRule, ruleMatches, applyRules, describe };
