// services/sharedFeed.js — the shared threat feed.
// When the same attacker hits several Genjutsu users, every user is protected from it.
//
// Built every 30 minutes from the saved scans (last 90 days, real accounts only):
//   • only DANGEROUS emails with a hard sign (look-alike domain, hidden link, failed sender checks,
//     dangerous file, Reply-To trick, Safe Browsing hit …) and not marked safe by the user or an admin
//   • indicators: the sender's domain (not for gmail.com and other public mail services, where the
//     exact sender address is used instead) and the domains of the links in the email
//   • an indicator becomes ACTIVE when 2 or more different users received it, or an admin confirmed it;
//     with one user it is only "watching"
//   • big real services (google.com, microsoft.com …) and link shorteners are never used as domains
//   • an admin can remove an indicator; it then never comes back by itself
// Only indicators are shared (domains, addresses, links), never anyone's email content.
const db = () => require('../database/db');
const { registrable, hostOf, addressOf, FREE_MAIL } = require('./detection');

const MIN_USERS = 2;
const NEVER = new Set(['google.com', 'gmail.com', 'googlemail.com', 'youtube.com', 'microsoft.com', 'outlook.com', 'live.com', 'office.com', 'office365.com',
  'hotmail.com', 'yahoo.com', 'apple.com', 'icloud.com', 'amazon.com', 'facebook.com', 'instagram.com', 'whatsapp.com', 'linkedin.com', 'twitter.com', 'x.com',
  'github.com', 'gitlab.com', 'cloudflare.com', 'amazonaws.com', 'sharepoint.com', 'onedrive.com', 'dropbox.com', 'zoom.us', 'paypal.com', 'docusign.net',
  'sendgrid.net', 'mailchimp.com', 'mailgun.org', 'list-manage.com', 'gstatic.com', 'googleusercontent.com', 'w3.org', 'schema.org',
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'genjutsu.org']);
const HARD = /look-alike|hidden link|reply-to|global block list|ip-address url|dangerous file type|double-extension|display-name spoofing|safe browsing|SPF: FAIL|DMARC: FAIL|payment-fraud|seen in attacks/i;

async function initSharedFeed() {
  await db().query(`
    CREATE TABLE IF NOT EXISTS shared_indicators (
      kind       TEXT NOT NULL,            -- domain | sender
      value      TEXT NOT NULL,
      users      INTEGER DEFAULT 0,
      emails     INTEGER DEFAULT 0,
      first_seen TIMESTAMPTZ,
      last_seen  TIMESTAMPTZ,
      status     TEXT DEFAULT 'watch',     -- watch | active | removed
      confirmed  INTEGER DEFAULT 0,
      removed_by TEXT,
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (kind, value)
    );`);
}

// Pure part (tested): turn dangerous-email rows into indicators
function indicatorsFrom(rows) {
  const map = new Map();
  const add = (kind, value, r) => {
    if (!value || NEVER.has(value)) return;
    const k = `${kind}|${value}`;
    const cur = map.get(k) || { kind, value, users: new Set(), emails: 0, first: r.at, last: r.at, confirmed: false };
    cur.users.add(r.user_id); cur.emails++;
    if (r.at < cur.first) cur.first = r.at; if (r.at > cur.last) cur.last = r.at;
    if (r.review === 'confirmed') cur.confirmed = true;
    map.set(k, cur);
  };
  for (const r of rows) {
    if (!HARD.test(r.details || '')) continue;
    const addr = addressOf(r.sender_email || '');
    const dom = registrable((addr.split('@')[1] || '').toLowerCase());
    if (dom && FREE_MAIL.has(dom)) add('sender', addr, r); else add('domain', dom, r);
    let urls = [];
    try { urls = (JSON.parse(r.iocs || '{}').urls || []); } catch (_) {}
    for (const u of new Set(urls.map(x => registrable(hostOf(x))).filter(Boolean))) if (u !== dom) add('domain', u, r);
  }
  return [...map.values()].map(x => ({ ...x, users: x.users.size, status: (x.users.size >= MIN_USERS || x.confirmed) ? 'active' : 'watch' }));
}

async function rebuild() {
  const { query } = db();
  const { rows } = await query(`
    SELECT e.user_id, e.sender_email, e.scanned_at AS at, sr.details, sr.iocs,
           (SELECT status FROM threat_reviews r WHERE r.email_id = e.email_id ORDER BY r.reviewed_at DESC LIMIT 1) AS review
    FROM emails e
    JOIN LATERAL (SELECT threat_type, details, iocs FROM scan_results WHERE email_id = e.email_id ORDER BY scan_timestamp DESC LIMIT 1) sr ON TRUE
    LEFT JOIN LATERAL (SELECT new_level FROM threat_overrides WHERE email_id = e.email_id ORDER BY overridden_at DESC LIMIT 1) ov ON TRUE
    WHERE e.user_id NOT LIKE 'demo-%' AND e.scanned_at > NOW() - interval '90 days'
      AND COALESCE(ov.new_level, sr.threat_type) = 'dangerous'`);
  const inds = indicatorsFrom(rows.filter(r => r.review !== 'false_positive'));
  for (const i of inds) {
    await query(`INSERT INTO shared_indicators (kind, value, users, emails, first_seen, last_seen, status, confirmed, updated_at)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
                 ON CONFLICT (kind, value) DO UPDATE SET users=EXCLUDED.users, emails=EXCLUDED.emails, first_seen=LEAST(shared_indicators.first_seen, EXCLUDED.first_seen),
                   last_seen=EXCLUDED.last_seen, confirmed=EXCLUDED.confirmed, updated_at=NOW(),
                   status = CASE WHEN shared_indicators.status='removed' THEN 'removed' ELSE EXCLUDED.status END`,
      [i.kind, i.value, i.users, i.emails, i.first, i.last, i.status, i.confirmed ? 1 : 0]);
  }
  // nothing new for 90 days: drop it (removed ones stay so they never come back)
  await query(`DELETE FROM shared_indicators WHERE status <> 'removed' AND last_seen < NOW() - interval '90 days'`);
  cache.at = 0;
  return { indicators: inds.length, active: inds.filter(i => i.status === 'active').length };
}

// What scans check against (refreshed every 5 minutes)
const cache = { at: 0, domains: new Map(), senders: new Map() };
async function getActive() {
  if (Date.now() - cache.at < 5 * 60 * 1000) return cache;
  try {
    const { rows } = await db().query(`SELECT kind, value, users FROM shared_indicators WHERE status='active'`);
    cache.domains = new Map(rows.filter(r => r.kind === 'domain').map(r => [r.value, r.users]));
    cache.senders = new Map(rows.filter(r => r.kind === 'sender').map(r => [r.value, r.users]));
  } catch (_) { /* scanning works without the feed */ }
  cache.at = Date.now();
  return cache;
}

function startSharedFeed() {
  const run = () => rebuild().then(r => { if (r.active) console.log(`🌐 Shared threat feed: ${r.active} active indicators`); })
    .catch(e => console.warn('⚠️  Shared feed:', e.message));
  setTimeout(run, 60 * 1000).unref?.();
  setInterval(run, 30 * 60 * 1000).unref?.();
}

const list = async () => (await db().query(`SELECT * FROM shared_indicators ORDER BY (status='active') DESC, users DESC, last_seen DESC LIMIT 300`)).rows;
async function setStatus(kind, value, status, by) {
  await db().query(`UPDATE shared_indicators SET status=$3, removed_by=$4, updated_at=NOW() WHERE kind=$1 AND value=$2`, [kind, value, status, status === 'removed' ? by : null]);
  cache.at = 0;
}

module.exports = { initSharedFeed, indicatorsFrom, rebuild, getActive, startSharedFeed, list, setStatus, NEVER, MIN_USERS };
