// services/threatRecords.js — one saved scan (with its override and quarantine state)
// turned into the email shape the app shows. Used by the Threats page and the dashboard
// so both always count the same way.
const parseJSON = (s, d) => { try { return s ? JSON.parse(s) : d; } catch { return d; } };
function recordToEmail(r) {
  const level = r.override_level || r.threat_type || 'safe';
  const iocs = parseJSON(r.iocs, null);
  return {
    id: r.gmail_message_id, dbId: r.email_id,
    from: r.sender_email || '', subject: r.subject || '', date: r.received_date || r.scanned_at,
    body: r.body_text || '', snippet: (r.body_text || '').slice(0, 160),
    links: iocs?.urls || [], attachments: parseJSON(r.attachment_scan, []).map(a => ({ filename: a.filename || a.name || '' })).filter(a => a.filename),
    quarantined: r.blocked_reason === 'auto', blocked: !!r.blocked_reason, fromRecord: true,
    adminRemark: r.override_note || null, overrideLevel: r.override_level || null, overriddenBy: r.overridden_by || null, overriddenAt: r.overridden_at || null,
    threat: {
      level, originalLevel: r.threat_type, scannedAt: r.scanned_at, score: Math.round((r.confidence_score || 0) * 100),
      reasons: parseJSON(r.details, []), subType: r.threat_subtype || (level === 'safe' ? null : 'phishing'),
      mitre: parseJSON(r.mitre, []), iocs, category: r.category || null, country: r.origin_country || null,
      authDetails: { raw: r.auth_raw || '' },
      adminRemark: r.override_note || null, overrideLevel: r.override_level || null,
    },
  };
}


// Nepal date (YYYY-MM-DD) an email belongs to: when it arrived, else when it was scanned
const NPT_MS = (5 * 60 + 45) * 60 * 1000;
function nptDay(d) {
  const t = new Date(d).getTime();
  return isNaN(t) ? null : new Date(t + NPT_MS).toISOString().slice(0, 10);
}

// The threat type, worked out from the saved reasons alone. Same rules as the scanner
// (services/threatService.js), so old saved scans can be re-sorted without the original email.
function subtypeFromReasons(reasons) {
  const r = (reasons || []).join('\n');
  if (/^Safe Browsing:|Attachment: (double-extension|dangerous file type)|^Dangerous file contents:/m.test(r)) return 'malware_link';
  if (/^(Look-alike link domain|Hidden link|IP-address URL|Suspicious domain in link|New domain|On Genjutsu's global block list|Seen in attacks on)/m.test(r)) return 'phishing';
  if (/^(Display-name spoofing|Look-alike sender domain|Reply-To mismatch|Payment-fraud wording|Payment request wording|SPF:|DKIM:|DMARC:|Bank\/payment email from free)/m.test(r)) return 'spoofed_sender';
  if (/^(Phishing keyword|ML Classifier)/m.test(r)) return 'phishing';
  return 'other';
}

// One-time (and on demand): re-sort every saved threat with the current rules
async function reclassifyAll(query) {
  const { rows } = await query(`SELECT scan_id, details, threat_subtype FROM scan_results WHERE threat_type IN ('dangerous','suspicious')`);
  let changed = 0;
  for (const row of rows) {
    const next = subtypeFromReasons(parseJSON(row.details, []));
    if (next !== row.threat_subtype) { await query('UPDATE scan_results SET threat_subtype=$2 WHERE scan_id=$1', [row.scan_id, next]); changed++; }
  }
  return { checked: rows.length, changed };
}
const SUBTYPE_RULES_VERSION = '2';
async function reclassifyOnce(query) {
  const done = (await query(`SELECT value FROM system_settings WHERE key='subtype_rules_version'`)).rows[0]?.value;
  if (done === SUBTYPE_RULES_VERSION) return null;
  const r = await reclassifyAll(query);
  await query(`INSERT INTO system_settings (key, value, updated_by) VALUES ('subtype_rules_version', $1, 'system')
               ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value`, [SUBTYPE_RULES_VERSION]);
  return r;
}

module.exports = { recordToEmail, parseJSON, nptDay, NPT_MS, subtypeFromReasons, reclassifyAll, reclassifyOnce };
