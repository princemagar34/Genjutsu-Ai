// ============================================================
// services/insights.js — group raw detection reasons into the
// plain categories used by charts and the PDF report
// ============================================================
const CATEGORIES = [
  ['Pretends to be a brand',     /^display-name spoofing/i],
  ['Look-alike address',         /^look-alike/i],
  ['Replies go elsewhere',       /^reply-to mismatch/i],
  ['Hidden link',                /^hidden link/i],
  ['Payment fraud',              /^payment/i],
  ['Brand-new website',          /^(new|young) domain/i],
  ['Known bad link',             /safe ?browsing|malicious url|ip-address url|suspicious domain in link/i],
  ['Sender not verified',        /^(spf|dkim|dmarc)|bank\/payment email from free/i],
  ['Risky attachment',           /^attachment/i],
  ['Machine learning',           /classifier|bayes/i],
  ['Pushy wording',              /urgen|nlp|tone/i],
  ['Phishing words',             /phishing keyword/i],
  ['Lots of links',              /link count/i],
  ['Your rules',                 /^your rule/i]
];
function categoryOf(reason) {
  for (const [name, re] of CATEGORIES) if (re.test(String(reason || ''))) return name;
  return null;
}
const parseJSON = (v, d) => { try { return v ? JSON.parse(v) : d; } catch (_) { return d; } };

// rows: [{ sender_email, level, details(json reasons), mitre(json), iocs(json) }]
function summarise(rows) {
  const checks = {}, domains = {}, mitre = {};
  const ioc = { emails: new Set(), domains: new Set(), urls: new Set(), ips: new Set(), attachments: new Set() };
  for (const r of rows) {
    if (r.level === 'safe') continue;
    const reasons = parseJSON(r.details, []);
    new Set(reasons.map(categoryOf).filter(Boolean)).forEach(c => { checks[c] = (checks[c] || 0) + 1; });
    const addr = ((String(r.sender_email || '').match(/<([^>]+)>/) || [])[1] || String(r.sender_email || '')).toLowerCase();
    const dom = addr.split('@')[1];
    if (dom) domains[dom] = (domains[dom] || 0) + 1;
    parseJSON(r.mitre, []).forEach(m => { mitre[m.id] = mitre[m.id] || { id: m.id, name: m.name, count: 0 }; mitre[m.id].count++; });
    const i = parseJSON(r.iocs, null);
    if (i) Object.keys(ioc).forEach(k => (i[k] || []).forEach(v => ioc[k].add(v)));
  }
  const top = (o, n) => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, n).map(([label, count]) => ({ label, count }));
  return {
    checks: top(checks, 10),
    domains: top(domains, 6),
    mitre: Object.values(mitre).sort((a, b) => b.count - a.count),
    iocs: Object.fromEntries(Object.entries(ioc).map(([k, v]) => [k, [...v]]))
  };
}

module.exports = { categoryOf, summarise, parseJSON };
