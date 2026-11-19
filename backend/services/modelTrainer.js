// services/modelTrainer.js — keeps the Naive Bayes model learning from real scams.
//
// 1. collect(): saves new examples with labels we can trust (see SOURCES) into
//    training_samples, with addresses, links and long numbers taken out.
// 2. train():   builds a new model from the saved examples, tests it on 1 in 5
//    examples it never saw, and only switches to it when it is at least as good
//    as the current model on the same test. Every version is kept, so an admin
//    can switch back.
// Users marking an email "safe" on their own never teach the model (a scammer with
// an account could otherwise teach it that scams are safe); an admin has to agree.
const crypto  = require('crypto');
const natural = require('natural');
const ml      = require('./mlService');

const db = () => require('../database/db');
const MAX_PER_CLASS = 2500;      // newest examples kept per label for one training run
const MIN_REAL_PER_CLASS = 15;   // below this there is too little real data to bother
const PER_SOURCE_PER_RUN = 400;
const LOCK_ID = 734211;

// ── Taking personal details out of the text ─────────────────
// names: the recipient's own name and email, so a saved example never says who received it
function redact(text, names = []) {
  let out = String(text || '');
  for (const nm of names.filter(x => x && x.length >= 3)) {
    out = out.replace(new RegExp(`\\b${nm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'gi'), ' recipientname ');
  }
  return out
    .replace(/<[^>]+>/g, ' ')
    .replace(/[\w.+-]+@[\w-]+(\.[\w-]+)+/g, ' emailaddress ')
    .replace(/https?:\/\/([^\s/?#]+)[^\s]*/gi, (_, host) => ` link ${host.replace(/^www\./, '')} `)
    .replace(/\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{20,60}|0x[a-fA-F0-9]{40}|T[A-Za-z1-9]{33})\b/g, ' cryptowallet ')
    .replace(/\+?\d[\d\s-]{7,}\d/g, ' longnumber ')
    .replace(/\s+/g, ' ').trim().slice(0, 1500);
}

// ── Where trusted examples come from ────────────────────────
const NOT_DEMO = (col) => `${col} NOT LIKE 'demo-%'`;
const HARD = `(sr.details ~* '(look-alike|hidden link|reply-to|global block list|ip address|dangerous attachment|display name|spf=?\\s*fail|dmarc=?\\s*fail|safe browsing)')`;
const SOURCES = [
  { source: 'dataset', label: 'both', note: "Genjutsu's starter dataset (scams and normal emails from Nepal and worldwide, in data/)", sql: null },
  { source: 'honeypot', label: 'phishing', note: 'Messages scammers sent to Nami',
    sql: `SELECT m.message_id AS ref, s.user_id, COALESCE(s.subject,'') || ' ' || COALESCE(m.body,'') AS text
          FROM honeypot_messages m JOIN honeypot_sessions s ON s.session_id = m.session_id
          WHERE m.direction='inbound' AND ${NOT_DEMO('s.user_id')} AND length(COALESCE(m.body,'')) > 20` },
  { source: 'admin_confirmed', label: 'phishing', note: 'Threats an admin confirmed',
    sql: `SELECT DISTINCT ON (e.email_id) e.email_id AS ref, e.user_id, COALESCE(e.subject,'') || ' ' || COALESCE(e.body_text,'') AS text
          FROM threat_reviews r JOIN emails e ON e.email_id = r.email_id WHERE r.status='confirmed' AND ${NOT_DEMO('e.user_id')}` },
  { source: 'blocklist', label: 'phishing', note: 'Emails from domains blocked for everyone',
    sql: `SELECT e.email_id AS ref, e.user_id, COALESCE(e.subject,'') || ' ' || COALESCE(e.body_text,'') AS text
          FROM emails e JOIN global_blocklist b
            ON b.domain = lower(split_part(substring(e.sender_email from '[^<@[:space:]]+@[^>[:space:]]+'), '@', 2))
          WHERE ${NOT_DEMO('e.user_id')}` },
  { source: 'auto_clear', label: 'phishing', note: 'Very clear detections (score 80+ with a hard sign like a look-alike domain)',
    sql: `SELECT e.email_id AS ref, e.user_id, COALESCE(e.subject,'') || ' ' || COALESCE(e.body_text,'') AS text
          FROM emails e
          JOIN LATERAL (SELECT threat_type, details FROM scan_results WHERE email_id=e.email_id ORDER BY scan_timestamp DESC LIMIT 1) sr ON TRUE
          WHERE e.confidence_score >= 0.8 AND sr.threat_type='dangerous' AND ${HARD} AND ${NOT_DEMO('e.user_id')}
            AND NOT EXISTS (SELECT 1 FROM threat_overrides o WHERE o.email_id=e.email_id)` },
  { source: 'admin_false_alarm', label: 'safe', note: 'False alarms an admin agreed with',
    sql: `SELECT DISTINCT ON (e.email_id) e.email_id AS ref, e.user_id, COALESCE(e.subject,'') || ' ' || COALESCE(e.body_text,'') AS text
          FROM threat_reviews r JOIN emails e ON e.email_id = r.email_id WHERE r.status='false_positive' AND ${NOT_DEMO('e.user_id')}` },
  { source: 'newsletter', label: 'safe', note: 'Verified newsletters (signed by the sender, with an unsubscribe link)',
    sql: `SELECT e.email_id AS ref, e.user_id, COALESCE(e.subject,'') || ' ' || COALESCE(e.body_text,'') AS text
          FROM emails e JOIN LATERAL (SELECT category FROM scan_results WHERE email_id=e.email_id ORDER BY scan_timestamp DESC LIMIT 1) sr ON TRUE
          WHERE sr.category='newsletter' AND ${NOT_DEMO('e.user_id')}
            AND NOT EXISTS (SELECT 1 FROM threat_overrides o WHERE o.email_id=e.email_id)` },
  { source: 'auto_clean', label: 'safe', note: 'Clean emails: passed DMARC and scored 10 or less',
    sql: `SELECT e.email_id AS ref, e.user_id, COALESCE(e.subject,'') || ' ' || COALESCE(e.body_text,'') AS text
          FROM emails e WHERE e.dmarc_result='pass' AND e.is_phishing=0 AND e.confidence_score <= 0.10 AND ${NOT_DEMO('e.user_id')}
            AND NOT EXISTS (SELECT 1 FROM threat_overrides o WHERE o.email_id=e.email_id)` },
];
// When two sources disagree about the same email, the more trustworthy one wins
const PRIORITY = { dataset: 2, admin_confirmed: 5, admin_false_alarm: 5, honeypot: 4, blocklist: 3, newsletter: 2, auto_clear: 1, auto_clean: 1 };

async function initTrainingDb() {
  const { query } = db();
  await query(`
    CREATE TABLE IF NOT EXISTS training_samples (
      sample_id  TEXT PRIMARY KEY,
      label      TEXT NOT NULL CHECK (label IN ('phishing','safe')),
      source     TEXT NOT NULL,
      source_ref TEXT NOT NULL,
      user_id    TEXT,
      text       TEXT NOT NULL,
      added_at   TIMESTAMPTZ DEFAULT NOW(),
      excluded   INTEGER DEFAULT 0,
      UNIQUE (source, source_ref)
    );
    CREATE INDEX IF NOT EXISTS training_samples_added ON training_samples (added_at DESC);
    ALTER TABLE ml_models ADD COLUMN IF NOT EXISTS model_json TEXT;
    ALTER TABLE ml_models ADD COLUMN IF NOT EXISTS metrics    TEXT;
    ALTER TABLE ml_models ADD COLUMN IF NOT EXISTS samples    INTEGER;
    ALTER TABLE ml_models ADD COLUMN IF NOT EXISTS status     TEXT;
    ALTER TABLE ml_models ADD COLUMN IF NOT EXISTS trained_by TEXT;
  `);
}

// ── 0. The starter dataset (backend/data/dataset_*.txt) ──────
// One example per line: "region|text". Loaded once; editing a line adds it as a new example.
function readDataset() {
  const fs = require('fs'), path = require('path');
  const out = [];
  for (const [file, label] of [['dataset_scam.txt', 'phishing'], ['dataset_safe.txt', 'safe']]) {
    const p = path.join(__dirname, '..', 'data', file);
    if (!fs.existsSync(p)) continue;
    for (const line of fs.readFileSync(p, 'utf8').split('\n')) {
      const m = line.match(/^(\w+)\|(.+)$/);
      if (m) out.push({ label, region: m[1], text: m[2].trim() });
    }
  }
  return out;
}
async function loadDataset() {
  const { query } = db();
  let n = 0;
  for (const d of readDataset()) {
    const ref = 'ds-' + crypto.createHash('sha1').update(d.label + '|' + d.text).digest('hex').slice(0, 16);
    const r = await query(`INSERT INTO training_samples (sample_id, label, source, source_ref, user_id, text)
                           VALUES ($1,$2,'dataset',$3,NULL,$4) ON CONFLICT (source, source_ref) DO NOTHING`,
      [`ts-${crypto.randomBytes(8).toString('hex')}`, d.label, ref, d.text]);
    n += r.rowCount || 0;
  }
  if (n) console.log(`🧠 Added ${n} examples from the starter dataset`);
  return n;
}

// ── 1. Collect new examples ─────────────────────────────────
async function collect() {
  const { query } = db();
  const added = {};
  for (const s of SOURCES) {
    if (!s.sql) continue;
    let rows = [];
    try {
      rows = (await query(`SELECT c.*, u.username, u.email AS user_email FROM (${s.sql}) c LEFT JOIN users u ON u.user_id = c.user_id
        WHERE NOT EXISTS (SELECT 1 FROM training_samples t WHERE t.source=$1 AND t.source_ref=c.ref)
        LIMIT ${PER_SOURCE_PER_RUN}`, [s.source])).rows;
    } catch (e) { console.warn(`[train] source ${s.source} skipped:`, e.message); continue; }
    let n = 0;
    for (const r of rows) {
      const names = [...String(r.username || '').split(/\s+/), String(r.user_email || '').split('@')[0]];
      const text = redact(r.text, names);
      if (ml.cleanText(text).split(' ').length < 4) continue;      // too short to learn from
      await query(`INSERT INTO training_samples (sample_id, label, source, source_ref, user_id, text)
                   VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (source, source_ref) DO NOTHING`,
        [`ts-${crypto.randomBytes(8).toString('hex')}`, s.label, s.source, String(r.ref), r.user_id || null, text]);
      n++;
    }
    added[s.source] = n;
  }
  return added;
}

// ── 2. Build, test, and maybe switch ────────────────────────
const isTest = (ref) => crypto.createHash('sha1').update(String(ref)).digest()[0] % 5 === 0;   // the same 1 in 5 every time

// Pure part (tested in tests/): pick examples, build a model, score it
function prepare(rows) {
  const best = new Map();                       // one label per email/message, the most trusted source wins
  for (const r of rows) {
    const cur = best.get(r.source_ref);
    if (!cur || (PRIORITY[r.source] || 0) > (PRIORITY[cur.source] || 0)) best.set(r.source_ref, r);
  }
  const all = [...best.values()].sort((a, b) => new Date(b.added_at || 0) - new Date(a.added_at || 0));
  let phish = all.filter(r => r.label === 'phishing'), safe = all.filter(r => r.label === 'safe');
  // keep the two labels roughly balanced (at most 3 to 1), newest first
  const cap = (a, b) => a.slice(0, Math.min(MAX_PER_CLASS, Math.max(MIN_REAL_PER_CLASS, b.length * 3)));
  [phish, safe] = [cap(phish, safe), cap(safe, phish)];
  const use = [...phish, ...safe];
  return { train: use.filter(r => !isTest(r.source_ref)), test: use.filter(r => isTest(r.source_ref)), counts: { phishing: phish.length, safe: safe.length } };
}
function build(trainRows) {
  const c = new natural.BayesClassifier();
  ml.PHISHING_SAMPLES.forEach(t => c.addDocument(t, 'phishing'));   // the original examples always stay in
  ml.SAFE_SAMPLES.forEach(t => c.addDocument(t, 'safe'));
  for (const r of trainRows) { const t = ml.cleanText(r.text); if (t) c.addDocument(t, r.label); }
  c.train();
  return c;
}
// Same rule the scanner uses: phishing only above 60% confidence
function predict(c, text) {
  const cleaned = ml.cleanText(text);
  const sc = c.getClassifications(cleaned);
  const p = Math.abs(sc.find(s => s.label === 'phishing')?.value || 0), s = Math.abs(sc.find(x => x.label === 'safe')?.value || 0);
  return p / ((p + s) || 1) > 0.6 ? 'phishing' : 'safe';
}
function evaluate(c, testRows) {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  for (const r of testRows) {
    const got = predict(c, r.text);
    if (r.label === 'phishing') got === 'phishing' ? tp++ : fn++;
    else got === 'phishing' ? fp++ : tn++;
  }
  const n = testRows.length || 1, precision = tp / ((tp + fp) || 1), recall = tp / ((tp + fn) || 1);
  return { tested: testRows.length, accuracy: +((tp + tn) / n).toFixed(4), precision: +precision.toFixed(4), recall: +recall.toFixed(4),
    f1: +((2 * precision * recall) / ((precision + recall) || 1)).toFixed(4), falseAlarms: fp, missed: fn };
}
// Switch only if the new model is at least as good (1 point of slack) and not worse at catching scams
const better = (nw, old) => !old || (nw.f1 >= old.f1 - 0.01 && nw.recall >= old.recall - 0.03);

let currentClassifier = null;   // the live retrained model (null = built-in)
async function train({ by = 'scheduler', force = false } = {}) {
  const { pool, query } = db();
  const lock = await pool.connect();
  try {
    if (!(await lock.query('SELECT pg_try_advisory_lock($1) AS ok', [LOCK_ID])).rows[0].ok)
      return { status: 'busy', message: 'Training is already running somewhere else.' };
    const added = await collect();
    const rows = (await query(`SELECT label, source, source_ref, text, added_at FROM training_samples WHERE excluded=0 ORDER BY added_at DESC LIMIT 12000`)).rows;
    const { train: tr, test, counts } = prepare(rows);
    if (counts.phishing < MIN_REAL_PER_CLASS || counts.safe < MIN_REAL_PER_CLASS)
      return { status: 'not_enough_data', added, counts, message: `Need at least ${MIN_REAL_PER_CLASS} scam and ${MIN_REAL_PER_CLASS} safe examples (have ${counts.phishing} and ${counts.safe}).` };
    const last = (await query(`SELECT samples FROM ml_models WHERE is_active=1 LIMIT 1`)).rows[0];
    if (!force && last?.samples === tr.length + test.length)
      return { status: 'no_change', added, counts, message: 'No new examples since the last training.' };

    const candidate = build(tr);
    const mNew = evaluate(candidate, test);
    const live = currentClassifier || build([]);          // built-in model = seeds only
    const mOld = evaluate(live, test);
    const promote = test.length >= 6 && better(mNew, mOld);
    const id = `model-${Date.now()}`, version = `auto-${new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '')}`;
    await query(`INSERT INTO ml_models (model_id, model_name, version, accuracy, is_active, model_json, metrics, samples, status, trained_by)
                 VALUES ($1,$2,$3,$4,0,$5,$6,$7,$8,$9)`,
      [id, 'Genjutsu Naive Bayes (retrained)', version, mNew.accuracy, JSON.stringify(candidate),
       JSON.stringify({ ...mNew, previous: mOld, counts, trainSize: tr.length }), tr.length + test.length, promote ? 'active' : 'rejected', by]);
    if (promote) await activate(id, candidate, version);
    await query(`DELETE FROM ml_models WHERE model_json IS NOT NULL AND is_active=0 AND model_id NOT IN
                 (SELECT model_id FROM ml_models WHERE model_json IS NOT NULL ORDER BY created_at DESC LIMIT 15)`);   // keep the last 15 versions
    return { status: promote ? 'promoted' : 'rejected', id, version, added, counts, metrics: mNew, previous: mOld,
      message: promote ? `New model is live: ${Math.round(mNew.accuracy * 100)}% accurate on ${mNew.tested} unseen emails (old one: ${Math.round(mOld.accuracy * 100)}%).`
                       : `Kept the current model: the new one was not better on ${mNew.tested} unseen emails (${Math.round(mNew.accuracy * 100)}% vs ${Math.round(mOld.accuracy * 100)}%).` };
  } finally {
    try { await lock.query('SELECT pg_advisory_unlock($1)', [LOCK_ID]); } catch (_) {}
    lock.release();
  }
}

async function activate(id, classifier, version) {
  const { query } = db();
  if (!classifier) {
    const row = (await query('SELECT model_json, version FROM ml_models WHERE model_id=$1', [id])).rows[0];
    if (!row) throw new Error('Model not found');
    version = row.version;
    classifier = row.model_json ? natural.BayesClassifier.restore(JSON.parse(row.model_json)) : null;
  }
  await query('UPDATE ml_models SET is_active = CASE WHEN model_id=$1 THEN 1 ELSE 0 END', [id]);
  if (classifier) { currentClassifier = classifier; ml.setClassifier(classifier, version); }
  else { currentClassifier = null; ml.setClassifier(build([]), 'built-in'); }   // switching back to the original model
  return version;
}

// Load the live model at startup, and pick up a model another server instance trained
let loadedId = null;
async function loadActive() {
  const { query } = db();
  const row = (await query('SELECT model_id, version, model_json FROM ml_models WHERE is_active=1 LIMIT 1')).rows[0];
  if (!row || row.model_id === loadedId) return;
  loadedId = row.model_id;
  if (row.model_json) {
    currentClassifier = natural.BayesClassifier.restore(JSON.parse(row.model_json));
    ml.setClassifier(currentClassifier, row.version);
    console.log(`🧠 Using retrained model ${row.version}`);
  }
}

function startTrainingScheduler() {
  if (process.env.ML_AUTO_TRAIN === 'false') return;
  const run = async () => {
    try {
      const r = await train({ by: 'scheduler' });
      if (!['no_change', 'busy'].includes(r.status)) console.log(`🧠 Model training: ${r.message}`);
    } catch (e) { console.warn('⚠️  Model training failed:', e.message); }
  };
  setTimeout(run, 3 * 60 * 1000).unref?.();
  setInterval(run, 24 * 60 * 60 * 1000).unref?.();
  setInterval(() => loadActive().catch(() => {}), 10 * 60 * 1000).unref?.();
}

// For the admin portal
async function overview() {
  const { query } = db();
  const [counts, models, recent] = await Promise.all([
    query(`SELECT source, label, COUNT(*)::int AS n, COUNT(*) FILTER (WHERE excluded=1)::int AS excluded FROM training_samples GROUP BY source, label`),
    query(`SELECT model_id, model_name, version, accuracy, is_active, created_at, metrics, samples, status, trained_by, (model_json IS NOT NULL) AS retrained
           FROM ml_models ORDER BY created_at DESC LIMIT 15`),
    query(`SELECT sample_id, label, source, left(text, 220) AS text, added_at, excluded FROM training_samples ORDER BY added_at DESC LIMIT 60`),
  ]);
  return { sources: SOURCES.map(({ source, label, note }) => ({ source, label, note, ...(() => { const rs = counts.rows.filter(x => x.source === source);
      return { n: rs.reduce((a, r) => a + r.n, 0), excluded: rs.reduce((a, r) => a + r.excluded, 0), scam: rs.filter(r => r.label === 'phishing').reduce((a, r) => a + r.n, 0), safe: rs.filter(r => r.label === 'safe').reduce((a, r) => a + r.n, 0) }; })() })),
    models: models.rows.map(m => ({ ...m, metrics: (() => { try { return JSON.parse(m.metrics || 'null'); } catch { return null; } })() })),
    recent: recent.rows, live: ml.getModelVersion(), autoTrain: process.env.ML_AUTO_TRAIN !== 'false' };
}
const excludeSample = (id, on = true) => db().query('UPDATE training_samples SET excluded=$2 WHERE sample_id=$1', [id, on ? 1 : 0]);

module.exports = { redact, SOURCES, readDataset, loadDataset, initTrainingDb, collect, prepare, build, evaluate, better, train, activate, loadActive, startTrainingScheduler, overview, excludeSample, isTest };
