// ============================================================
// services/siem.js — turn Genjutsu findings into SIEM events
//   jsonl : one JSON object per line (Elastic, Splunk HEC, Wazuh)
//   cef   : ArcSight Common Event Format
//   syslog: RFC 5424 lines carrying CEF
// ============================================================
const VERSION = '3.1';
const cefEsc = (v) => String(v ?? '').replace(/\\/g, '\\\\').replace(/=/g, '\\=').replace(/\r?\n/g, ' ');
const cefHdr = (v) => String(v ?? '').replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
const parse = (v, d) => { try { return v ? JSON.parse(v) : d; } catch (_) { return d; } };
const addr = (v) => ((String(v || '').match(/<([^>]+)>/) || [])[1] || String(v || '')).trim();

// rows from getSiemRows(): threat emails + account actions
function toEvents(user, threatRows, activityRows) {
  const events = threatRows.map(r => {
    const reasons = parse(r.details, []);
    const mitre = parse(r.mitre, []);
    const iocs = parse(r.iocs, {}) || {};
    const score = Math.round((r.confidence_score || 0) * 100);
    return {
      '@timestamp': new Date(r.scanned_at).toISOString(),
      event: { kind: 'alert', category: ['email', 'threat'], type: ['indicator'], action: 'email-threat-detected', severity: score, provider: 'genjutsu' },
      email: { from: { address: addr(r.sender_email) }, to: { address: user.email }, subject: r.subject, delivery_timestamp: r.received_date },
      threat: { indicator: { type: 'email-message' }, level: r.threat_type, subtype: r.threat_subtype || null, technique: mitre.map(m => ({ id: m.id, name: m.name })) },
      genjutsu: { score, reasons, iocs, message_id: r.gmail_message_id }
    };
  });
  for (const a of activityRows) {
    events.push({
      '@timestamp': new Date(a.at).toISOString(),
      event: { kind: 'event', category: ['email'], action: a.action.toLowerCase().replace(/\s+/g, '-'), provider: 'genjutsu' },
      user: { email: user.email }, message: `${a.action}${a.detail ? ': ' + a.detail : ''}`
    });
  }
  return events.sort((x, y) => x['@timestamp'].localeCompare(y['@timestamp']));
}

function toCef(ev) {
  const isAlert = ev.event.kind === 'alert';
  const sev = isAlert ? Math.max(1, Math.min(10, Math.round((ev.event.severity || 0) / 10))) : 3;
  const sigId = isAlert ? `EMAIL-${String(ev.threat.level || 'threat').toUpperCase()}` : `ACTION-${ev.event.action.toUpperCase()}`;
  const name = isAlert ? `${ev.threat.level === 'dangerous' ? 'Dangerous' : 'Suspicious'} email detected` : ev.message;
  const ext = isAlert
    ? { rt: Date.parse(ev['@timestamp']), suser: ev.email.from.address, duser: ev.email.to.address, msg: ev.email.subject,
        cs1Label: 'mitre', cs1: (ev.threat.technique || []).map(t => t.id).join(','), cs2Label: 'reasons', cs2: (ev.genjutsu.reasons || []).slice(0, 5).join('; '),
        cs3Label: 'iocDomains', cs3: (ev.genjutsu.iocs.domains || []).join(','), request: (ev.genjutsu.iocs.urls || [])[0] || '', cn1Label: 'score', cn1: ev.event.severity }
    : { rt: Date.parse(ev['@timestamp']), suser: ev.user.email, msg: ev.message };
  const extStr = Object.entries(ext).filter(([, v]) => v !== '' && v != null).map(([k, v]) => `${k}=${cefEsc(v)}`).join(' ');
  return `CEF:0|Genjutsu|Email Security|${VERSION}|${cefHdr(sigId)}|${cefHdr(name)}|${sev}|${extStr}`;
}

function toSyslog(ev, host = 'genjutsu') {
  const pri = ev.event.kind === 'alert' ? (ev.threat.level === 'dangerous' ? 130 : 132) : 134; // local0.crit / warning / info
  return `<${pri}>1 ${ev['@timestamp']} ${host} genjutsu - ${ev.event.kind === 'alert' ? 'threat' : 'action'} - ${toCef(ev)}`;
}

function render(events, format) {
  if (format === 'cef')    return { type: 'text/plain', ext: 'cef', body: events.map(toCef).join('\n') + '\n' };
  if (format === 'syslog') return { type: 'text/plain', ext: 'log', body: events.map(e => toSyslog(e)).join('\n') + '\n' };
  return { type: 'application/x-ndjson', ext: 'jsonl', body: events.map(e => JSON.stringify(e)).join('\n') + '\n' };
}

module.exports = { toEvents, toCef, toSyslog, render };
