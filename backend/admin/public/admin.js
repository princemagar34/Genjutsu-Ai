// Genjutsu Admin — SOC triage interface
'use strict';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const n = (x) => Number(x || 0).toLocaleString('en-US');
const COUNTRY = (() => { let d; try { d = new Intl.DisplayNames(['en'], { type: 'region' }); } catch (_) {} return (c) => !c || c === '??' ? 'Unknown' : (d ? (d.of(c) || c) : c); })();
const time = (d) => d ? new Date(d).toLocaleString('en-GB', { timeZone: 'Asia/Kathmandu', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false }) : '—';
const hm = (d) => d ? new Date(d).toLocaleTimeString('en-GB', { timeZone: 'Asia/Kathmandu', hour: '2-digit', minute: '2-digit', hour12: false }) : '';
const ago = (d) => {
  if (!d) return '';
  const s = Math.max(0, (Date.now() - new Date(d)) / 1000);
  return s < 3600 ? `${Math.max(1, Math.round(s / 60))}M` : s < 86400 ? `${Math.round(s / 3600)}H` : `${Math.round(s / 86400)}D`;
};
const mins = (m) => m >= 60 ? `${Math.floor(m / 60)}h ${m % 60}m` : `${m || 0}m`;
const parseList = (v) => { if (Array.isArray(v)) return v; try { return JSON.parse(v || '[]'); } catch { return []; } };

let me = null;
const can = (p) => !!me?.permissions?.includes(p);

// ── API ───────────────────────────────────────────────────────
async function api(path, opts = {}) {
  const res = await fetch('/admin/api' + path, {
    credentials: 'include', ...opts,
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    body: opts.body && typeof opts.body !== 'string' ? JSON.stringify(opts.body) : opts.body,
  });
  let data = {};
  try { data = await res.json(); } catch (_) {}
  if (res.status === 401 && data.expired) { showLogin(data.error); throw new Error(data.error); }
  if (res.status === 423) { toast(data.error, true); throw new Error(data.error); }
  if (!res.ok || data.success === false) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}
const post = (p, body) => api(p, { method: 'POST', body: body || {} });

function toast(msg, bad = false) {
  const t = $('#toast'); t.textContent = msg; t.className = 'toast' + (bad ? ' bad' : ''); t.hidden = false;
  clearTimeout(toast._t); toast._t = setTimeout(() => { t.hidden = true; }, 4200);
}
function modal(title, html, wide = false) {
  $('#modal > div').style.maxWidth = wide ? 'min(1100px, 96vw)' : '';
  $('#modal > div').style.width = wide ? 'min(1100px, 96vw)' : '';
  $('#modalTitle').textContent = title; $('#modalBody').innerHTML = html; $('#modal').hidden = false;
  setTimeout(() => ($('#modalBody input, #modalBody select, #modalBody textarea, #modalBody button') || $('#modal [data-act=close-modal]')).focus(), 30);
}
const closeModal = () => { $('#modal').hidden = true; };
async function run(btn, fn) {
  if (btn) btn.disabled = true;
  try { await fn(); } catch (e) { toast(e.message, true); } finally { if (btn) btn.disabled = false; }
}

// ── Theme (black / white) ─────────────────────────────────────
function setTheme(t) {
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem('gj-admin-theme', t); } catch (_) {}
  $$('.theme-toggle').forEach(b => { b.innerHTML = `<i aria-hidden="true"></i>${t === 'dark' ? 'White' : 'Black'}`; b.setAttribute('aria-label', t === 'dark' ? 'Switch to the white look' : 'Switch to the black look'); });
}

// ── Sign in ───────────────────────────────────────────────────
function showLogin(note) {
  me = null;
  $('#app').hidden = true; $('#login').hidden = false;
  $('#stepPassword').hidden = false; $('#stepCode').hidden = true;
  $('#loginNote').hidden = !note; $('#loginNote').textContent = note || '';
  $('#loginErr').hidden = true;
  setTimeout(() => $('#le').focus(), 30);
}
let recoveryMode = false;
function wireLogin() {
  $('#stepPassword').addEventListener('submit', async (e) => {
    e.preventDefault();
    const err = $('#loginErr'); err.hidden = true;
    const btn = e.submitter; btn.disabled = true;
    try {
      const r = await fetch('/admin/api/login', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: $('#le').value.trim(), password: $('#lp').value }) });
      const d = await r.json();
      if (!d.success) throw new Error(d.error || 'Could not sign in');
      $('#lp').value = '';
      if (d.needs2fa) { recoveryMode = false; setCodeMode(); $('#stepPassword').hidden = true; $('#stepCode').hidden = false; $('#lc').focus(); return; }
      me = d.admin; boot();
    } catch (x) { err.textContent = x.message === 'Failed to fetch' ? 'Cannot reach the server.' : x.message; err.hidden = false; }
    finally { btn.disabled = false; }
  });
  $('#stepCode').addEventListener('submit', async (e) => {
    e.preventDefault();
    const err = $('#codeErr'); err.hidden = true;
    const v = $('#lc').value.trim();
    try {
      const r = await fetch('/admin/api/login/2fa', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(recoveryMode ? { recovery: v } : { code: v }) });
      const d = await r.json();
      if (!d.success) { if (d.restart) return showLogin(d.error); throw new Error(d.error); }
      $('#lc').value = ''; me = d.admin; boot();
      if (recoveryMode) toast('Signed in with a recovery code. Set up 2-step login again on your new phone.');
    } catch (x) { err.textContent = x.message; err.hidden = false; $('#lc').select(); }
  });
  $('#useRecovery').addEventListener('click', (e) => { e.preventDefault(); recoveryMode = !recoveryMode; setCodeMode(); $('#lc').focus(); });
  $('#backToPw').addEventListener('click', (e) => { e.preventDefault(); showLogin(); });
}
function setCodeMode() {
  const lc = $('#lc');
  lc.value = '';
  if (recoveryMode) { lc.className = 'in mono'; lc.removeAttribute('maxlength'); lc.removeAttribute('pattern'); lc.inputMode = 'text'; $('#lcLabel').textContent = 'Recovery code'; $('#useRecovery').textContent = 'Use the app code instead'; }
  else { lc.className = 'in otp'; lc.maxLength = 6; lc.pattern = '[0-9]{6}'; lc.inputMode = 'numeric'; $('#lcLabel').textContent = 'Code'; $('#useRecovery').textContent = 'Lost your phone? Use a recovery code'; }
}

// ── Shell ─────────────────────────────────────────────────────
const TABS = [
  ['queue', 'Queue', 'queue'], ['wall', 'Wall', 'stats'], ['threats', 'Threats', 'threats'], ['attackers', 'Attackers', 'attackers'],
  ['users', 'Users', 'users'], ['honeypot', 'Honeypot', 'honeypot'], ['blocklist', 'Block list', 'attackers'], ['mistakes', 'Mistakes', 'mistakes'],
  ['announce', 'Announcements', 'stats'], ['reports', 'Reports', 'reports'], ['health', 'Health', 'health'], ['activity', 'Activity', 'activity'],
  ['model', 'Model', 'stats'], ['orgs', 'Organizations', 'orgs'], ['admins', 'Admins', 'admins'], ['settings', 'Settings', 'settings'],
];
// Pages about every organization at once: an organization admin never sees these (the server refuses them too)
const GLOBAL_TABS = new Set(['queue', 'blocklist', 'model', 'health', 'activity', 'reports', 'admins', 'settings', 'orgs']);
const tabOk = (t) => can(t[2]) && !(me.orgId && GLOBAL_TABS.has(t[0]));
let current = null;
function boot() {
  // Organization admins have their own, simpler portal
  if (me.orgId) { location.replace('/org/'); return; }
  $('#login').hidden = true; $('#app').hidden = false;
  $('#orgPortalBtn').hidden = me.role !== 'superadmin';
  $('#meBtn').textContent = `${me.name && me.name !== me.roleLabel ? me.name : me.email} · ${me.roleLabel}${me.orgName ? ' · ' + me.orgName : ''}`;
  $('#tabs').innerHTML = TABS.filter(tabOk).map(([id, label]) =>
    `<a href="#${id}" class="tab" data-tab="${id}">${label}${id === 'queue' ? ' <span class="n" id="qCount" hidden></span>' : ''}</a>`).join('');
  updateBanners();
  refreshStatus();
  clearInterval(boot._s); boot._s = setInterval(refreshStatus, 60000);
  route();
}
function updateBanners() {
  $('#roBanner').hidden = !me.readOnly;
  $('#twoFaBanner').hidden = !!me.twoFactor;
}
function route() {
  if (!me) return;
  let id = location.hash.replace('#', '').split('/')[0];
  const allowed = TABS.filter(tabOk).map(t => t[0]);
  if (!allowed.includes(id)) id = allowed[0] || 'wall';
  current = id;
  $$('.tab').forEach(a => a.classList.toggle('on', a.dataset.tab === id));
  $('#page').innerHTML = '<div class="empty">Loading…</div>';
  // A slower page that finishes after you moved on would overwrite the new one: draw the current page again
  const tok = ++route.tok;
  (PAGES[id] || PAGES.wall)().catch(e => { if (tok === route.tok) $('#page').innerHTML = `<div class="wrap"><div class="err">${esc(e.message)}</div></div>`; })
    .then(() => {
      if (tok === route.tok) route.drawn = tok;          // the current page is on screen
      else if (route.drawn === route.tok) route();       // an older page just covered it: draw the current one again
    });
}
route.tok = 0;
window.addEventListener('hashchange', route);

let wallCache = null;
async function refreshStatus() {
  try {
    const w = await api('/wall'); wallCache = w;
    const h = w.health, c = w.counts;
    const al = h?.alerts || {}, chans = [al.discord && 'DISCORD', al.email && 'EMAIL'].filter(Boolean);
    $('#statusStrip').innerHTML = (h ? [
      `<span class="${h.db.ok ? 'c-ok' : 'c-danger'}">● DB ${h.db.ok ? h.db.ms + 'ms' : 'DOWN'}</span>`,
      `<span class="${h.brokenConnections24h ? 'c-warn' : 'c-ok'}">● SCAN FAILURES 24H ${h.brokenConnections24h}</span>`,
      `<span class="${h.ai.configured ? 'c-ok' : 'c-warn'}">● AI ${h.ai.configured ? 'OK' : 'NO KEY'}</span>`,
      `<span class="${chans.length ? 'c-ok' : 'c-warn'}">● ALERTS ${chans.length ? chans.join(' + ') : 'NOT SET UP'}</span>`,
    ] : [`<span class="c-info">● ${esc((me.orgName || 'YOUR ORGANIZATION').toUpperCase())}</span>`]).concat([
      `<span>24H ${n(c.scanned)} SCANNED</span>`,
      `<span class="c-danger">${n(c.dangerous)} DANGEROUS</span>`,
      `<span class="c-warn">${n(c.suspicious)} SUSPICIOUS</span>`,
      `<span class="c-ok">${mins(c.minutesWasted)} WASTED</span>`,
    ]).join('');
  } catch (_) { /* the page itself shows errors */ }
  if (can('queue')) try { const q = await api('/queue'); setQueueCount(q.items.length); } catch (_) {}
}
function setQueueCount(k) { const el = $('#qCount'); if (el) { el.textContent = k; el.hidden = !k; } }
setInterval(() => { const c = $('#clock'); if (c) c.textContent = 'NPT ' + new Date().toLocaleTimeString('en-GB', { timeZone: 'Asia/Kathmandu', hour12: false }); }, 1000);

// Small shared renderers
const bars = (hourly) => {
  const by = {}; (hourly || []).forEach(h => { by[new Date(h.hour).getUTCHours()] = h.dangerous + h.suspicious; });
  const now = new Date(); const vals = [];
  for (let i = 23; i >= 0; i--) { const d = new Date(now - i * 36e5); vals.push(by[d.getUTCHours()] || 0); }
  const max = Math.max(1, ...vals);
  return `<div class="bars" role="img" aria-label="Threats per hour, last 24 hours">${vals.map(v => `<span style="height:${Math.max(3, v / max * 100)}%" title="${v}"></span>`).join('')}</div>`;
};
const originBars = (rows, limit = 6) => {
  const total = rows.reduce((a, r) => a + r.n, 0) || 1, max = Math.max(1, ...rows.map(r => r.n));
  return rows.length ? rows.slice(0, limit).map(r => `<div class="hbar"><span>${esc(COUNTRY(r.country))}</span><i style="width:${r.n / max * 100}%;${r.country === '??' ? 'background:var(--chip)' : ''}"></i><span class="mono" style="text-align:right">${Math.round(r.n / total * 100)}%</span></div>`).join('')
    + `<p class="sub" style="margin:8px 0 0;line-height:1.5">From the sending server's IP address. Scammers can hide behind VPNs, so treat this as a hint, not proof.</p>`
    : '<p class="sub">No data yet. New scans record where emails were sent from.</p>';
};
const feedList = (rows) => rows.length ? `<ul class="feed">${rows.slice(0, 8).map(f => `<li><span class="mono c-muted">${hm(f.scanned_at)}</span><span><span class="lv ${esc(f.level)}">${f.level === 'dangerous' ? 'DANGER' : 'SUSPECT'}</span> ${esc((f.sender_email || '').replace(/.*</, '').replace(/>.*/, ''))} → ${esc((f.user_email || '').split('@')[0])}${f.origin_country ? ` <span class="mono c-muted">· ${esc(f.origin_country)}</span>` : ''}</span></li>`).join('')}</ul>` : '<p class="sub">Nothing flagged yet.</p>';
const trendBars = (t) => {
  if (!t?.labels?.length) return '<p class="sub">No data yet.</p>';
  const max = Math.max(1, ...t.threats.map((x, i) => x + t.safe[i]));
  return `<div style="display:flex;gap:8px;align-items:flex-end;height:110px" role="img" aria-label="Threats and safe emails per day">${t.labels.map((l, i) => `
    <div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;height:100%;justify-content:flex-end">
      <div style="width:100%;display:flex;flex-direction:column;justify-content:flex-end;flex:1">
        <span title="${t.threats[i]} threats" style="display:block;background:var(--danger);height:${t.threats[i] / max * 100}%;min-height:${t.threats[i] ? 2 : 0}px"></span>
        <span title="${t.safe[i]} safe" style="display:block;background:var(--chip);height:${t.safe[i] / max * 100}%"></span></div>
      <span class="mono sub" style="font-size:10px">${esc(String(l).slice(0, 6))}</span></div>`).join('')}</div>
    <p class="sub" style="margin:8px 0 0"><span class="dot c-danger"></span>threats <span class="dot" style="color:var(--chip);margin-left:10px"></span>safe</p>`;
};
const typeBars = (S) => {
  const rows = [['Phishing', S.subtypes?.phishing], ['Malware (links & files)', S.subtypes?.malware_link], ['Spoofed senders', S.subtypes?.spoofed_sender], ['Other', S.subtypes?.other]]
    .map(([k, v]) => ({ k, v: v || 0 }));
  const max = Math.max(1, ...rows.map(r => r.v));
  return rows.map(r => `<div class="hbar"><span>${r.k}</span><i style="width:${r.v / max * 100}%"></i><span class="mono" style="text-align:right">${n(r.v)}</span></div>`).join('')
    + `<p class="sub" style="margin:8px 0 0">Dangerous ${n(S.dangerousCount)} · Suspicious ${n(S.suspiciousCount)}</p>`;
};
const attackerList = (rows) => rows.length ? `<ol class="mono" style="margin:0;padding-left:18px;font-size:12px;line-height:2">${rows.slice(0, 6).map(a => `<li><a href="#attackers/${encodeURIComponent(a.domain)}">${esc(a.domain)}</a> <span class="c-muted">${a.users}</span></li>`).join('')}</ol>` : '<p class="sub">No attackers in the last 7 days.</p>';

// ============================================================
// PAGES
// ============================================================
const PAGES = {};
const TYPE_LABEL = { campaign: 'CAMPAIGN', mistake: 'FALSE ALARM?', approval: 'APPROVAL', user: 'USER', nami: 'NAMI', login: 'LOGIN' };
const FILTERS = [['all', 'All'], ['campaign', 'Threats'], ['user', 'Users'], ['approval', 'Approvals'], ['mistake', 'False alarms'], ['nami', 'Nami'], ['login', 'Logins']];
let queue = [], qFilter = 'all', qSel = null;

// ── Queue ─────────────────────────────────────────────────────
PAGES.queue = async () => {
  const [q, w] = await Promise.all([api('/queue'), wallCache ? Promise.resolve(wallCache) : api('/wall')]);
  queue = q.items; setQueueCount(queue.length);
  if (!queue.find(i => i.key === qSel)) qSel = queue[0]?.key || null;
  $('#page').innerHTML = `<div class="triage">
    <section class="q-col" aria-label="Needs action">
      <div class="q-head"><h1 class="h" style="margin:0">Needs action · ${queue.length}</h1>
        <div class="chips" role="group" aria-label="Filter">${FILTERS.filter(([k]) => k === 'all' || q.counts[k]).map(([k, l]) =>
          `<button class="chip ${qFilter === k ? 'on' : ''}" type="button" data-act="q-filter" data-k="${k}">${l}${k !== 'all' ? ' ' + q.counts[k] : ''}</button>`).join('')}</div></div>
      <div id="qList"></div>
    </section>
    <section class="detail" id="qDetail" aria-live="polite"></section>
    <aside class="aside" aria-label="Live">
      <section><h2 class="h">Threats · 24h</h2>${bars(w.hourly)}</section>
      <section><h2 class="h">Live detections</h2>${feedList(w.feed)}</section>
      <section><h2 class="h">Where attacks come from · 7d</h2>${originBars(w.origins)}</section>
      <section><h2 class="h">Top attackers · 7d</h2>${attackerList(w.attackers)}</section>
    </aside></div>`;
  renderQueueList(); renderQueueDetail();
};
function renderQueueList() {
  const list = queue.filter(i => qFilter === 'all' || i.type === qFilter);
  $('#qList').innerHTML = list.length ? list.map(i => `<button type="button" class="q ${i.key === qSel ? 'on' : ''}" data-act="q-open" data-key="${esc(i.key)}">
      <div class="top"><span class="lv t-${i.type}">${TYPE_LABEL[i.type]}</span><span class="ago">${ago(i.at)}</span></div>
      <div class="t">${esc(i.title)}</div><div class="s">${esc(i.sub)}</div></button>`).join('')
    : `<div class="empty">Nothing needs you right now.</div>`;
}
async function renderQueueDetail() {
  const box = $('#qDetail'); if (!box) return;
  const it = queue.find(i => i.key === qSel);
  if (!it) { box.innerHTML = `<div class="empty"><h2 style="margin:0 0 6px;font-size:18px;color:var(--text)">All clear</h2>New campaigns, false alarms, approvals and broken connections show up here.</div>`; return; }
  box.innerHTML = '<div class="empty">Loading…</div>';
  try { box.innerHTML = await (DETAIL[it.type] || DETAIL.generic)(it); }
  catch (e) { box.innerHTML = `<div class="err">${esc(e.message)}</div>`; }
}
const doneBtn = (it, label = 'Mark done') => `<button class="btn" type="button" data-act="q-done" data-key="${esc(it.key)}">${label}</button>`;
const reasonsList = (r) => r.length ? `<ul class="reasons">${r.map(x => `<li>${esc(x.text || x)}${x.n > 1 ? ` <span class="c-muted mono">×${x.n}</span>` : ''}</li>`).join('')}</ul>` : '<p class="sub">No reasons recorded.</p>';
const mitreChips = (m) => m.length ? m.map(x => `<span class="pill mono" style="margin:0 6px 6px 0">${esc(x.id)} ${esc(x.name || '')}</span>`).join('') : '';

const DETAIL = {
  async campaign(it) { return attackerView(it.ref, it); },
  async mistake(it) {
    const m = (await api('/mistakes')).mistakes.find(x => x.email_id === it.ref);
    if (!m) return `<div class="empty">This one was already handled.</div>${doneBtn(it)}`;
    return `<header class="row" style="align-items:flex-start"><div class="grow"><span class="lv t-mistake">FALSE ALARM? · WAS ${esc(m.original_level)} · SCORE ${m.score}</span>
        <h2>${esc(m.user_email)} says this email is safe</h2><p class="mono sub" style="margin:0">${esc(m.sender_email)} · ${time(m.overridden_at)}</p></div></header>
      <section class="box"><h3 class="h">Subject</h3><p style="margin:0">${esc(m.subject || '(no subject)')}</p>${m.note ? `<h3 class="h" style="margin-top:14px">Their note</h3><p style="margin:0">${esc(m.note)}</p>` : ''}</section>
      <section class="box"><h3 class="h">Why Genjutsu flagged it</h3>${reasonsList(parseList(m.details))}</section>
      <p class="sub" style="margin:0">Your answer is recorded as a review. It helps you see where detection needs tuning.</p>
      ${can('review') ? `<div class="row"><button class="btn primary" type="button" data-act="mistake" data-id="${esc(m.email_id)}" data-status="false_positive" data-key="${esc(it.key)}">They're right: it's safe</button>
      <button class="btn" type="button" data-act="mistake" data-id="${esc(m.email_id)}" data-status="confirmed" data-key="${esc(it.key)}">Keep the warning</button></div>` : doneBtn(it)}`;
  },
  async approval(it) {
    const a = (await api('/actions')).pending.find(x => x.action_id === it.ref);
    if (!a) return `<div class="empty">Already decided.</div>`;
    const mine = a.requested_by === me.email;
    return `<span class="lv t-approval">APPROVAL NEEDED</span><h2>${esc(a.summary)}</h2>
      <p class="mono sub" style="margin:0">ASKED BY ${esc(a.requested_by)} · ${time(a.requested_at)}</p>
      <section class="box"><p style="margin:0;line-height:1.6">Risky changes need a second admin. ${mine ? 'You asked for this, so another Super Admin has to approve it.' : 'Approve only if you know why it is needed.'}</p></section>
      ${!mine && can('approve') ? `<div class="row"><button class="btn primary" type="button" data-act="decide" data-id="${esc(a.action_id)}" data-d="approve">Approve</button>
        <button class="btn ghost-danger" type="button" data-act="decide" data-id="${esc(a.action_id)}" data-d="reject">Reject</button></div>` : ''}`;
  },
  async user(it) {
    const d = await api(`/users/${encodeURIComponent(it.ref)}/detail`);
    return `<span class="lv t-user">USER</span><h2>${esc(it.title)}</h2>
      <section class="box"><h3 class="h">Last error</h3><p class="mono" style="margin:0;font-size:13px">${esc(d.user.last_scan_error || 'No error recorded: nothing was scanned for a week although they signed in.')}</p></section>
      ${userSummary(d)}
      <section class="box"><h3 class="h">What to do</h3><p style="margin:0;line-height:1.6">Usually their Gmail or Outlook access expired or was removed. Ask them to sign out of Genjutsu and sign in again. App passwords for other mail providers may have been changed.</p></section>
      <div class="row">${doneBtn(it, 'Mark done')}<a class="btn" href="mailto:${esc(d.user.email)}?subject=${encodeURIComponent('Genjutsu: please sign in again')}">Email them</a></div>`;
  },
  async login(it) {
    return `<span class="lv t-login">LOGIN FROM A NEW DEVICE</span><h2>${esc(it.sub.split(' · ')[0])}</h2>
      <p class="mono sub" style="margin:0">${esc(it.sub)} · ${time(it.at)}</p>
      <section class="box"><p style="margin:0;line-height:1.6">If this wasn't them, change that admin's password straight away${can('admins') ? ' and turn their account off on the Admins page' : ''}. Their 2-step login also needs resetting if their phone was lost.</p></section>
      <div class="row">${doneBtn(it, 'It was them')}${can('admins') ? '<a class="btn ghost-danger" href="#admins">Go to Admins</a>' : ''}</div>`;
  },
  async nami(it) {
    const d = await api('/intel');
    const rows = d.rows.filter(r => r.session === it.ref);
    return `<span class="lv t-nami">NAMI · SCAMMER DETAILS</span><h2>${esc(it.title)}</h2>
      <p class="mono sub" style="margin:0">${esc(rows[0]?.scammer || '')} · ${esc(rows[0]?.subject || '')}</p>
      <section class="box tw"><table class="t"><thead><tr><th>Type</th><th>Value</th><th>Seen</th></tr></thead><tbody>
      ${rows.map(r => `<tr><td>${esc(INTEL_LABEL[r.type] || r.type)}</td><td class="mono">${esc(r.value)}</td><td class="mono c-muted">${time(r.seen)}</td></tr>`).join('')}</tbody></table></section>
      <p class="sub" style="margin:0">Report bank accounts to the bank and Nepal Police Cyber Bureau (cyberbureau.nepalpolice.gov.np). Crypto wallets can be reported to the exchange.</p>
      <div class="row">${doneBtn(it, 'Mark reported')}<a class="btn" href="/admin/api/intel.csv">Download all as CSV</a></div>`;
  },
  async generic(it) { return `<h2>${esc(it.title)}</h2><p>${esc(it.sub)}</p>${doneBtn(it)}`; },
};
const INTEL_LABEL = { bankAccounts: 'Bank account', ibans: 'IBAN', swift: 'SWIFT', crypto: 'Crypto wallet', phones: 'Phone', whatsapp: 'WhatsApp', telegram: 'Telegram', emails: 'Email', urls: 'Link' };

async function attackerView(domain, it) {
  const d = await api(`/attackers/${encodeURIComponent(domain)}`);
  const q = d.users.reduce((a, u) => a + u.quarantined, 0);
  const topC = Object.entries(d.countries).sort((a, b) => b[1] - a[1])[0];
  const csv = `type,value\ndomain,${d.domain}\n${d.ips.map(ip => `ip,${ip}`).join('\n')}`;
  return `<header class="row" style="align-items:flex-start"><div class="grow" style="flex-basis:300px">
      <span class="lv t-campaign">${d.blocked ? 'BLOCKED FOR EVERYONE' : 'CAMPAIGN · DANGEROUS'}</span>
      <h2><span class="mono">${esc(d.domain)}</span> hit ${d.users.length} user${d.users.length === 1 ? '' : 's'}</h2>
      <p class="mono sub" style="margin:0">FIRST SEEN ${time(d.firstSeen)} · LAST SEEN ${ago(d.lastSeen)} AGO · ${d.emails} EMAILS</p></div>
      ${it ? doneBtn(it, 'Ignore') : ''}
      <a class="btn" download="iocs-${esc(d.domain)}.csv" href="data:text/csv;charset=utf-8,${encodeURIComponent(csv)}">Export IOCs</a>
      ${can('blocklist') ? (d.blocked ? `<button class="btn" type="button" data-act="unblock" data-domain="${esc(d.domain)}">Unblock</button>`
        : `<button class="btn danger" type="button" data-act="block" data-domain="${esc(d.domain)}" ${it ? `data-key="${esc(it.key)}"` : ''}>Block for everyone</button>`) : ''}
    </header>
    <section class="grid g4">
      <div><div class="h" style="margin:0">Pretends to be</div><div class="mid">${esc(d.lookalike ? d.lookalike[0].toUpperCase() + d.lookalike.slice(1) : '—')}</div></div>
      <div><div class="h" style="margin:0">Domain age</div><div class="mid mono">${d.ageDays == null ? 'unknown' : d.ageDays + ' days'}</div></div>
      <div><div class="h" style="margin:0">Quarantined</div><div class="mid mono">${q} / ${d.emails}</div></div>
      <div><div class="h" style="margin:0">Sent from</div><div class="mid">${topC ? esc(COUNTRY(topC[0])) : 'unknown'}</div>${d.ips[0] ? `<div class="mono sub" style="margin-top:4px">${esc(d.ips[0].replace(/\.\d+\.\d+$/, '.x.x'))}</div>` : ''}</div>
    </section>
    <section class="box"><h3 class="h">Why it was flagged</h3>${reasonsList(d.reasons)}<div style="margin-top:10px">${mitreChips(d.mitre)}</div></section>
    <section class="box tw"><h3 class="h">Users hit · ${d.users.length}</h3><table class="t"><thead><tr><th>User</th><th>Emails</th><th>Status</th></tr></thead><tbody>
      ${d.users.map(u => `<tr><td class="mono">${esc(u.user)}</td><td class="mono">${u.emails}</td><td class="${u.quarantined === u.emails ? 'c-ok' : 'c-warn'}">${u.quarantined === u.emails ? 'Quarantined' : u.quarantined ? `${u.quarantined} quarantined, ${u.emails - u.quarantined} in inbox` : 'In inbox (quarantine off)'}</td></tr>`).join('')}
    </tbody></table></section>`;
}
function userSummary(d) {
  const u = d.user, s = d.stats || {};
  return `<section class="grid g4">
    <div><div class="h" style="margin:0">Mailbox</div><div class="mid">${esc(u.provider || 'google')}</div></div>
    <div><div class="h" style="margin:0">Emails scanned</div><div class="mid mono">${n(s.emails)}</div></div>
    <div><div class="h" style="margin:0">Threats</div><div class="mid mono c-danger">${n(s.threats)}</div></div>
    <div><div class="h" style="margin:0">Quarantined</div><div class="mid mono">${n(s.quarantined)}</div></div></section>
    <dl class="kv box"><dt>Last sign-in</dt><dd>${time(u.last_login)}</dd><dt>Last good scan</dt><dd>${time(u.last_scan_at)}</dd>
      <dt>Quarantine</dt><dd>${d.settings.auto_block ? 'On' : 'Off'}</dd><dt>Honeypot</dt><dd>${d.settings.honeypot_mode ? 'On · ' + esc(d.settings.honeypot_persona || '') : 'Off'}</dd>
      <dt>Rules</dt><dd>${d.rules.length ? d.rules.map(r => `${esc(r.action)} ${esc(r.field)} "${esc(r.value)}"`).join(', ') : 'None'}</dd>
      <dt>Trusted senders</dt><dd>${d.safeSenders.length ? esc(d.safeSenders.slice(0, 6).join(', ')) + (d.safeSenders.length > 6 ? ` +${d.safeSenders.length - 6}` : '') : 'None'}</dd>
      <dt>API keys</dt><dd>${d.apiKeys.length}</dd><dt>Weekly digest</dt><dd>${d.settings.weekly_digest ? 'On' : 'Off'}</dd></dl>`;
}

// ── Wall ──────────────────────────────────────────────────────
PAGES.wall = async () => {
  const [w, st, tr] = await Promise.all([api('/wall'), api('/stats'), api('/trend?days=7').catch(() => ({ trend: null }))]);
  wallCache = w;
  const S = st.stats, T = tr.trend;
  // The last 24 hours are in the status strip at the top; attack origins and top attackers
  // live on the Attackers page (and beside the Queue); admin events on the Activity page.
  $('#page').innerHTML = `<div class="wrap">
    <section class="grid g4" aria-label="All time">
      <div><div class="big">${n(S.totalUsers)}</div><div class="sub">users</div></div>
      <div><div class="big">${n(S.totalEmails)}</div><div class="sub">emails scanned</div></div>
      <div><div class="big c-danger">${n(S.totalThreats)}</div><div class="sub">threats caught</div></div>
      <div><div class="big">${n(S.totalHoneypot)}</div><div class="sub">honeypot chats · ${n(S.activeHoneypot)} active</div></div>
      <div><div class="big c-ok">${mins(S.totalMinutesWasted)}</div><div class="sub">scammer time wasted</div></div>
      <div><div class="big">${n(S.totalAlerts)}</div><div class="sub">alerts sent</div></div>
    </section>
    <div class="cols">
      <section class="box"><h2 class="h">Threats per hour · last 24h</h2>${bars(w.hourly)}</section>
      <section class="box"><h2 class="h">Last 7 days · threats vs safe</h2>${trendBars(T)}</section>
      <section class="box"><h2 class="h">Threats by type · all time</h2>${typeBars(S)}</section>
    </div>
    <section class="box tw"><h2 class="h">Live detections</h2>
      ${w.feed.length ? `<table class="t"><thead><tr><th>Time</th><th>Level</th><th>Sender → user</th><th>Technique</th><th>From</th><th>Score</th></tr></thead><tbody>
      ${w.feed.map(f => `<tr><td class="mono">${hm(f.scanned_at)}</td><td class="lv ${esc(f.level)}">${f.level === 'dangerous' ? 'DANGER' : 'SUSPECT'}</td>
        <td class="mono ell">${esc((f.sender_email || '').replace(/.*</, '').replace(/>.*/, ''))} → ${esc(f.user_email || '')}</td>
        <td>${esc(parseList(f.mitre)[0]?.id || '')}</td><td>${esc(COUNTRY(f.origin_country))}</td><td class="mono">${f.score}</td></tr>`).join('')}</tbody></table>` : '<p class="sub">Nothing flagged yet.</p>'}
    </section></div>`;
};

// ── Threats ───────────────────────────────────────────────────
let threats = [];
PAGES.threats = async () => {
  const d = await api('/blocked'); threats = d.blocked;
  $('#page').innerHTML = `<div class="wrap">
    <section class="grid g4">
      <div><div class="big">${n(d.summary.total)}</div><div class="sub">flagged emails</div></div>
      <div><div class="big c-danger">${n(d.summary.dangerous)}</div><div class="sub">dangerous</div></div>
      <div><div class="big c-warn">${n(d.summary.suspicious)}</div><div class="sub">suspicious</div></div>
      <div><div class="big">${n(d.summary.overridden)}</div><div class="sub">changed by an admin</div></div>
    </section>
    <div class="row"><label class="sr" for="tq">Search threats</label><input class="in grow" id="tq" placeholder="Search sender, subject or user" style="max-width:420px">
      <label class="sr" for="tl">Level</label><select class="in" id="tl" style="width:auto"><option value="">All levels</option><option value="dangerous">Dangerous</option><option value="suspicious">Suspicious</option><option value="changed">Changed by an admin</option></select>
      <span class="sub" id="tCount"></span></div>
    <section class="box tw" id="tTable"></section></div>`;
  $('#tq').addEventListener('input', drawThreats); $('#tl').addEventListener('change', drawThreats); drawThreats();
};
function drawThreats() {
  const q = $('#tq').value.toLowerCase(), l = $('#tl').value;
  const list = threats.filter(t => (!l || (l === 'changed' ? !!t.overrideLevel : t.threatType === l)) && (!q || `${t.senderEmail} ${t.subject} ${t.userEmail}`.toLowerCase().includes(q)));
  $('#tCount').textContent = `${list.length} shown`;
  $('#tTable').innerHTML = list.length ? `<table class="t"><thead><tr><th>Time</th><th>Level</th><th>Sender</th><th>Subject</th><th>User</th><th>From</th><th>Score</th><th></th></tr></thead><tbody>
    ${list.slice(0, 400).map(t => `<tr><td class="mono">${time(t.scannedAt)}</td><td class="lv ${esc(t.threatType)}">${esc(t.threatType)}${t.overrideLevel ? ' *' : ''}</td>
      <td class="mono ell">${esc(t.senderEmail)}</td><td class="ell">${esc(t.subject)}${t.overrideNote ? `<div class="sub ell" title="${esc(t.overrideNote)}" style="color:var(--info)">💬 ${esc(t.overrideNote)}${t.overriddenBy ? ` · ${esc(t.overriddenBy)}` : ''}</div>` : ''}</td><td class="mono ell">${esc(t.userEmail)}</td>
      <td>${esc(t.country || '')}</td><td class="mono">${t.score}</td>
      <td class="row" style="flex-wrap:nowrap">${can('review') ? `<button class="btn sm" type="button" data-act="review" data-id="${esc(t.emailId)}">Review</button>` : ''}
        ${can('override_threat') ? `<button class="btn sm" type="button" data-act="override" data-id="${esc(t.emailId)}">Change level</button>` : ''}
        <button class="btn sm" type="button" data-act="why" data-id="${esc(t.emailId)}">Why</button></td></tr>`).join('')}</tbody></table>
    ${list.length > 400 ? '<p class="sub">Showing the newest 400. Search to narrow down.</p>' : ''}` : '<div class="empty">No threats match.</div>';
}

// ── Attackers ─────────────────────────────────────────────────
PAGES.attackers = async () => {
  const sel = decodeURIComponent(location.hash.split('/')[1] || '');
  const days = PAGES.attackers.days || 7;
  const d = await api(`/attackers?days=${days}`);
  $('#page').innerHTML = `<div class="wrap">
    <div class="row"><h1 class="h grow" style="margin:0">Top attacking domains</h1><label class="sr" for="ad">Period</label>
      <select class="in" id="ad" style="width:auto">${[1, 7, 30, 90].map(x => `<option value="${x}" ${x === days ? 'selected' : ''}>Last ${x === 1 ? '24 hours' : x + ' days'}</option>`).join('')}</select></div>
    <div class="cols">
      <section class="box tw" style="grid-column:span 2">${d.attackers.length ? `<table class="t"><thead><tr><th>Domain</th><th>Users hit</th><th>Emails</th><th>Max score</th><th>From</th><th>Last seen</th><th></th></tr></thead><tbody>
        ${d.attackers.map(a => `<tr class="click" data-act="attacker" data-domain="${esc(a.domain)}"><td class="mono">${esc(a.domain)}</td><td class="mono">${a.users}</td><td class="mono">${a.emails}</td><td class="mono">${a.max_score}</td><td>${esc(COUNTRY(a.country))}</td><td class="mono">${ago(a.last_seen)}</td><td>${a.blocked ? '<span class="pill c-ok">Blocked</span>' : ''}</td></tr>`).join('')}</tbody></table>` : '<div class="empty">No attackers in this period.</div>'}</section>
      <section class="box"><h2 class="h">Where attacks come from</h2>${originBars(d.origins, 10)}</section>
    </div>
    <section id="attackerDetail" style="display:flex;flex-direction:column;gap:16px"></section></div>`;
  $('#ad').addEventListener('change', (e) => { PAGES.attackers.days = +e.target.value; route(); });
  if (sel) showAttacker(sel);
};
async function showAttacker(domain) {
  const box = $('#attackerDetail'); if (!box) return;
  box.innerHTML = '<div class="empty">Loading…</div>';
  try { box.innerHTML = await attackerView(domain); box.scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch (e) { box.innerHTML = `<div class="err">${esc(e.message)}</div>`; }
}

// ── Users ─────────────────────────────────────────────────────
let users = [], uFilter = 'all';
PAGES.users = async () => {
  users = (await api('/users/list')).users;
  const count = { all: users.length, problems: users.filter(u => u.last_scan_error).length, suspended: users.filter(u => u.is_suspended).length, demo: users.filter(u => u.demo).length };
  $('#page').innerHTML = `<div class="wrap">
    <div class="row"><label class="sr" for="uq">Search users</label><input class="in grow" id="uq" placeholder="Search email or name" style="max-width:380px">
      <div class="chips" style="margin:0">${[['all', 'All'], ['problems', 'Scan errors'], ['suspended', 'Suspended'], ['demo', 'Demo']].map(([k, l]) => `<button class="chip ${uFilter === k ? 'on' : ''}" type="button" data-act="u-filter" data-k="${k}">${l} ${count[k]}</button>`).join('')}</div></div>
    <section class="box tw" id="uTable"></section></div>`;
  $('#uq').addEventListener('input', drawUsers); drawUsers();
};
function drawUsers() {
  const q = ($('#uq')?.value || '').toLowerCase();
  const list = users.filter(u => (uFilter === 'all' || (uFilter === 'problems' && u.last_scan_error) || (uFilter === 'suspended' && u.is_suspended) || (uFilter === 'demo' && u.demo))
    && (!q || `${u.email} ${u.username}`.toLowerCase().includes(q)));
  $('#uTable').innerHTML = list.length ? `<table class="t"><thead><tr><th>User</th><th>Mailbox</th><th>Last sign-in</th><th>Last scan</th><th>Emails</th><th>Threats</th><th>Status</th></tr></thead><tbody>
    ${list.map(u => `<tr class="click" data-act="user" data-id="${esc(u.user_id)}"><td><div>${esc(u.username || '')}</div><div class="mono sub">${esc(u.email)}</div></td>
      <td>${esc(u.provider || 'google')}</td><td class="mono">${time(u.last_login)}</td>
      <td class="mono ${u.last_scan_error ? 'c-danger' : ''}">${u.last_scan_error ? 'Failing' : time(u.last_scan_at)}</td>
      <td class="mono">${n(u.emails)}</td><td class="mono">${n(u.threats)}</td>
      <td>${u.is_suspended ? '<span class="pill c-danger">Suspended</span>' : u.demo ? '<span class="pill c-muted">Demo</span>' : '<span class="pill c-ok">Active</span>'}</td></tr>`).join('')}</tbody></table>` : '<div class="empty">No users match.</div>';
}
async function openUser(id) {
  const d = await api(`/users/${encodeURIComponent(id)}/detail`);
  const u = d.user;
  modal(u.email, `${userSummary(d)}
    ${u.last_scan_error ? `<div class="err">Last scan failed: ${esc(u.last_scan_error)}</div>` : ''}
    <section><h3 class="h">Recent threats</h3>${d.threats.length ? `<table class="t"><tbody>${d.threats.slice(0, 8).map(t => `<tr><td class="lv ${esc(t.level)}">${esc(t.level)}</td><td class="ell">${esc(t.subject)}</td><td class="mono">${t.score}</td></tr>`).join('')}</tbody></table>` : '<p class="sub">None</p>'}</section>
    <section><h3 class="h">Honeypot</h3><p style="margin:0">${d.honeypot.length} conversation${d.honeypot.length === 1 ? '' : 's'}, ${mins(d.honeypot.reduce((a, h) => a + (h.minutes_wasted || 0), 0))} wasted</p></section>
    <section><h3 class="h">Recent activity</h3><ul class="mono" style="margin:0;padding-left:18px;font-size:12px;line-height:1.8">${d.activity.slice(0, 8).map(a => `<li>${time(a.created_at)} · ${esc(a.action)}</li>`).join('') || '<li class="c-muted">Nothing yet</li>'}</ul></section>
    ${can('suspend_user') && !String(u.user_id).startsWith('demo-') ? (u.is_suspended
      ? `<button class="btn" type="button" data-act="unsuspend" data-id="${esc(u.user_id)}" data-email="${esc(u.email)}">Unsuspend</button>`
      : `<div><label class="f" for="sr">Reason (they will see it)</label><input class="in" id="sr" maxlength="200" placeholder="e.g. Abuse of the honeypot"><div class="row" style="margin-top:10px"><button class="btn ghost-danger" type="button" data-act="suspend" data-id="${esc(u.user_id)}" data-email="${esc(u.email)}">Suspend this user</button></div></div>`) : ''}`);
}

// ── Honeypot ──────────────────────────────────────────────────
let hpFilter = 'all';
PAGES.honeypot = async () => {
  const [hp, intel] = await Promise.all([api('/honeypot/sessions'), can('intel') ? api('/intel') : api('/honeypot/leaderboard')]);
  const s = hp.stats, lb = intel.leaderboard || [];
  $('#page').innerHTML = `<div class="wrap">
    <section class="grid g4">
      <div><div class="big">${n(s.total)}</div><div class="sub">conversations</div></div>
      <div><div class="big c-ok">${n(s.active)}</div><div class="sub">active now</div></div>
      <div><div class="big">${mins(s.totalMinutes)}</div><div class="sub">scammer time wasted</div></div>
      <div><div class="big">${n(s.uniqueAttackers)}</div><div class="sub">different scammers</div></div>
    </section>
    <div class="cols">
      <section class="box tw" style="grid-column:span 2"><div class="row" style="margin-bottom:10px"><h2 class="h grow" style="margin:0">Conversations</h2>
        <div class="chips" style="margin:0">${[['all', 'All', hp.sessions.length], ['active', 'Active', hp.sessions.filter(x => x.status === 'active').length], ['ended', 'Ended', hp.sessions.filter(x => x.status !== 'active').length]].map(([k, l, c]) => `<button class="chip ${hpFilter === k ? 'on' : ''}" type="button" data-act="hp-filter" data-k="${k}">${l} ${c}</button>`).join('')}</div></div>${hp.sessions.length ? `<table class="t"><thead><tr><th>Scammer</th><th>User</th><th>Replies</th><th>Wasted</th><th>Status</th><th></th></tr></thead><tbody>
        ${hp.sessions.filter(x => hpFilter === 'all' || (hpFilter === 'active' ? x.status === 'active' : x.status !== 'active')).map(x => `<tr class="click" data-act="hp-open" data-id="${esc(x.sessionId)}"><td class="mono ell">${esc(x.senderEmail)}</td><td class="mono ell">${esc(x.userEmail || '')}</td><td class="mono">${x.repliesSent}</td><td class="mono">${mins(x.minutesWasted)}</td>
          <td>${x.status === 'active' ? '<span class="pill c-ok">Active</span>' : '<span class="pill c-muted">Ended</span>'}</td>
          <td>${x.status === 'active' && can('review') ? `<button class="btn sm" type="button" data-act="hp-end" data-id="${esc(x.sessionId)}">End</button>` : ''}</td></tr>`).join('')}</tbody></table>` : '<div class="empty">No honeypot conversations yet.</div>'}</section>
      <section class="box"><h2 class="h">Leaderboard · time wasted</h2>${lb.length ? `<ol style="margin:0;padding-left:20px;line-height:2;font-size:13px">${lb.map(l => `<li><span class="mono">${esc(l.user_email)}</span> <span class="c-muted">· ${mins(l.minutes)} · ${l.sessions} chats</span></li>`).join('')}</ol>` : '<p class="sub">No conversations yet.</p>'}</section>
    </div>
    ${can('intel') ? `<section class="box tw"><div class="row" style="margin-bottom:10px"><h2 class="h grow" style="margin:0">Scammer details collected by Nami · ${intel.rows.length}</h2><a class="btn sm" href="/admin/api/intel.csv">Download CSV</a></div>
      <p class="sub" style="margin:0 0 10px">${Object.entries(intel.totals).map(([k, v]) => `${v} ${esc((INTEL_LABEL[k] || k).toLowerCase())}${v === 1 ? '' : 's'}`).join(' · ') || 'Nothing yet.'}</p>
      ${intel.rows.length ? `<table class="t"><thead><tr><th>Type</th><th>Value</th><th>Scammer</th><th>Seen</th></tr></thead><tbody>${intel.rows.slice(0, 200).map(r => `<tr><td>${esc(INTEL_LABEL[r.type] || r.type)}</td><td class="mono">${esc(r.value)}</td><td class="mono ell">${esc(r.scammer)}</td><td class="mono">${time(r.seen)}</td></tr>`).join('')}</tbody></table>` : ''}</section>` : ''}
  </div>`;
};
async function openHoneypot(id) {
  const d = await api(`/honeypot/sessions/${encodeURIComponent(id)}/messages`);
  modal('Honeypot conversation', d.messages.length ? d.messages.map(m => `<div class="msg ${m.direction === 'inbound' ? 'in' : 'out'}"><div class="lv ${m.direction === 'inbound' ? 'dangerous' : 'safe'}" style="margin-bottom:6px">${m.direction === 'inbound' ? 'SCAMMER' : 'NAMI'} · ${time(m.sentAt)}</div>${esc(m.body)}</div>`).join('') : '<p class="sub">No messages yet.</p>');
}

// ── Block list ────────────────────────────────────────────────
PAGES.blocklist = async () => {
  const [d, f] = await Promise.all([api('/blocklist'), api('/shared-feed').catch(() => ({ indicators: [], minUsers: 2 }))]);
  const act = f.indicators.filter(i => i.status === 'active'), watch = f.indicators.filter(i => i.status === 'watch'), gone = f.indicators.filter(i => i.status === 'removed');
  $('#page').innerHTML = `<div class="wrap">
    <section class="box"><h1 class="h">Global block list</h1><p style="margin:0 0 14px;line-height:1.6;color:var(--text2)">Emails from these domains, or with links to them, are marked dangerous for every user (and quarantined where quarantine is on). Big email providers like gmail.com can't be blocked here.</p>
      ${can('blocklist') ? `<form class="row" data-form="block"><label class="sr" for="bd">Domain</label><input class="in grow" id="bd" placeholder="bad-site.com" style="max-width:300px" required>
        <label class="sr" for="br">Reason</label><input class="in grow" id="br" placeholder="Reason (optional)" style="max-width:360px"><button class="btn danger" type="submit">Block for everyone</button></form>` : ''}</section>
    <section class="box tw">${d.domains.length ? `<table class="t"><thead><tr><th>Domain</th><th>Reason</th><th>Blocked by</th><th>When</th><th>Caught since</th><th></th></tr></thead><tbody>
      ${d.domains.map(b => `<tr><td class="mono">${esc(b.domain)}</td><td>${esc(b.reason || '')}</td><td class="mono">${esc(b.added_by)}</td><td class="mono">${time(b.added_at)}</td><td class="mono">${n(b.hits_since)}</td>
        <td>${can('blocklist') ? `<button class="btn sm" type="button" data-act="unblock" data-domain="${esc(b.domain)}">Remove</button>` : ''}</td></tr>`).join('')}</tbody></table>` : '<div class="empty">Nothing blocked yet. Block a domain from a campaign in the Queue or on the Attackers page.</div>'}</section>
    <section class="box tw"><div class="row" style="margin-bottom:10px"><h2 class="h grow" style="margin:0">Shared threat feed (automatic) · ${act.length} active</h2>${can('blocklist') ? '<button class="btn sm" type="button" data-act="feed-rebuild">Update now</button>' : ''}</div>
      <p class="sub" style="margin:0 0 12px;line-height:1.6">When the same attacker sends dangerous emails to ${f.minUsers} or more users, every user is protected from it automatically. Only domains and sender addresses are shared, never email contents. Updated every 30 minutes. If one is wrong, remove it and it won't come back.</p>
      ${f.indicators.length ? `<table class="t"><thead><tr><th>Domain or sender</th><th>Users hit</th><th>Emails</th><th>Last seen</th><th>Status</th><th></th></tr></thead><tbody>
      ${[...act, ...watch, ...gone].map(i => `<tr style="${i.status === 'removed' ? 'opacity:.55' : ''}"><td class="mono">${esc(i.value)}${i.kind === 'sender' ? ' <span class="c-muted">(sender)</span>' : ''}</td><td class="mono">${i.users}</td><td class="mono">${i.emails}</td><td class="mono">${ago(i.last_seen)}</td>
        <td>${i.status === 'active' ? '<span class="pill c-danger">Protecting everyone</span>' : i.status === 'watch' ? `<span class="pill c-muted">Watching (1 user)</span>` : '<span class="pill c-muted">Removed</span>'}${i.confirmed ? ' <span class="c-info">· confirmed</span>' : ''}</td>
        <td>${can('blocklist') ? (i.status === 'removed' ? `<button class="btn sm" type="button" data-act="feed-status" data-kind="${esc(i.kind)}" data-value="${esc(i.value)}" data-status="active">Put back</button>` : i.status === 'active' ? `<button class="btn sm" type="button" data-act="feed-status" data-kind="${esc(i.kind)}" data-value="${esc(i.value)}" data-status="removed">Remove</button>` : '') : ''}</td></tr>`).join('')}</tbody></table>` : '<p class="sub">Nothing yet. It fills up as dangerous emails reach more than one user.</p>'}
    </section></div>`;
};

// ── Mistakes ──────────────────────────────────────────────────
PAGES.mistakes = async () => {
  const d = await api('/mistakes');
  $('#page').innerHTML = `<div class="wrap"><section class="box"><h1 class="h">Emails users said were safe</h1><p style="margin:0;line-height:1.6;color:var(--text2)">These were flagged, then the user marked them safe. If many look alike, detection needs tuning. Your review is saved.</p></section>
    <section class="box tw">${d.mistakes.length ? `<table class="t"><thead><tr><th>When</th><th>User</th><th>Sender</th><th>Subject</th><th>Was</th><th>Score</th><th>Review</th><th></th></tr></thead><tbody>
      ${d.mistakes.map(m => `<tr><td class="mono">${time(m.overridden_at)}</td><td class="mono ell">${esc(m.user_email)}</td><td class="mono ell">${esc(m.sender_email)}</td><td class="ell">${esc(m.subject)}</td>
        <td class="lv ${esc(m.original_level)}">${esc(m.original_level)}</td><td class="mono">${m.score}</td><td>${m.review === 'false_positive' ? '<span class="c-ok">Agreed</span>' : m.review === 'confirmed' ? '<span class="c-danger">Kept</span>' : '<span class="c-muted">—</span>'}</td>
        <td class="row" style="flex-wrap:nowrap">${can('review') && !m.review ? `<button class="btn sm" type="button" data-act="mistake" data-id="${esc(m.email_id)}" data-status="false_positive">Agree</button><button class="btn sm" type="button" data-act="mistake" data-id="${esc(m.email_id)}" data-status="confirmed">Keep warning</button>` : ''}
          <button class="btn sm" type="button" data-act="why" data-id="${esc(m.email_id)}" data-src="mistakes">Why</button></td></tr>`).join('')}</tbody></table>` : '<div class="empty">No disagreements. Nice.</div>'}</section></div>`;
  PAGES.mistakes.rows = d.mistakes;
};

// ── Announcements ─────────────────────────────────────────────
PAGES.announce = async () => {
  const d = await api('/announcements');
  const live = (a) => a.active && (!a.expires_at || new Date(a.expires_at) > new Date());
  $('#page').innerHTML = `<div class="wrap">
    ${can('announce') ? `<section class="box"><h1 class="h">Send a notice to every user</h1><p style="margin:0 0 14px;color:var(--text2)">It shows as a banner at the top of their app, e.g. "Maintenance tonight at 10 PM".</p>
      <form data-form="announce" style="display:flex;flex-direction:column;gap:12px"><label class="sr" for="am">Message</label><textarea class="in" id="am" rows="2" maxlength="280" required placeholder="Maintenance tonight at 10 PM. Scans pause for 15 minutes."></textarea>
      <div class="row"><label class="f" for="al" style="margin:0">Type</label><select class="in" id="al" style="width:auto"><option value="info">Info</option><option value="warning">Warning</option><option value="critical">Critical</option></select>
      <label class="f" for="ah" style="margin:0">Show for</label><select class="in" id="ah" style="width:auto"><option value="24">1 day</option><option value="72">3 days</option><option value="168">1 week</option><option value="0">Until I end it</option></select>
      <button class="btn primary" type="submit">Post notice</button></div></form></section>` : ''}
    <section class="box tw">${d.announcements.length ? `<table class="t"><thead><tr><th>Posted</th><th>Type</th><th>Message</th><th>By</th><th>Status</th><th></th></tr></thead><tbody>
      ${d.announcements.map(a => `<tr><td class="mono">${time(a.created_at)}</td><td>${esc(a.level)}</td><td>${esc(a.message)}</td><td class="mono">${esc(a.created_by)}</td>
        <td>${live(a) ? '<span class="pill c-ok">Showing</span>' : '<span class="pill c-muted">Ended</span>'}</td><td>${live(a) && can('announce') ? `<button class="btn sm" type="button" data-act="end-ann" data-id="${esc(a.announcement_id)}">End</button>` : ''}</td></tr>`).join('')}</tbody></table>` : '<div class="empty">No notices yet.</div>'}</section></div>`;
};

// ── Reports ───────────────────────────────────────────────────
PAGES.reports = async () => {
  const now = new Date(); const ym = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
  $('#page').innerHTML = `<div class="wrap"><div>
    <section class="box" style="max-width:720px"><h1 class="h">Monthly report (PDF)</h1><p style="margin:0 0 14px;line-height:1.6;color:var(--text2)">One page with emails checked, threats stopped, who attacked, where from, and scammer time wasted. Totals only, no email contents. Good for an organization, an investor or a pitch.</p>
      <div class="row"><label class="sr" for="rm">Month</label><input class="in" type="month" id="rm" value="${ym(now)}" max="${ym(now)}" style="width:auto"><button class="btn primary" type="button" data-act="report">Download PDF</button></div>
      <p class="sub" style="margin:14px 0 0">The admin log downloads from the Activity page, and scammer details from the Honeypot page.</p></section>
</div></div>`;
};

// ── Health ────────────────────────────────────────────────────
PAGES.health = async () => {
  const { health: h, problems } = await api('/health');
  const card = (label, ok, value, note) => `<div><div class="h" style="margin:0">${label}</div><div class="mid ${ok === true ? 'c-ok' : ok === false ? 'c-danger' : 'c-warn'}"><span class="dot"></span>${esc(value)}</div>${note ? `<div class="sub" style="margin-top:4px">${esc(note)}</div>` : ''}</div>`;
  const al = h.alerts || {}, chans = [al.discord && 'Discord', al.email && 'Email'].filter(Boolean);
  $('#page').innerHTML = `<div class="wrap">
    <section class="grid g4">
      ${card('Database', h.db.ok, h.db.ok ? `${h.db.ms} ms` : 'Down')}
      ${card('Last scan', !!h.lastScanAt, h.lastScanAt ? ago(h.lastScanAt) + ' ago' : 'Never')}
      ${card('Scan failures · 24h', h.brokenConnections24h === 0, String(h.brokenConnections24h))}
      ${card('AI (Nami, chat)', h.ai.configured || null, h.ai.configured ? 'Key set' : 'No GROQ_API_KEY', h.ai.configured ? '' : 'Nami uses simple replies without it')}
      ${card('Team alerts', chans.length ? true : null, chans.length ? chans.join(' + ') : 'Not set up', chans.length ? (al.threatAlerts ? 'Security + dangerous emails' : 'Security only') : 'Add a Discord webhook in Settings')}
      ${card('Safe Browsing', h.safeBrowsing.configured || null, h.safeBrowsing.configured ? 'Key set' : 'Not set up')}
      ${card('Google sign-in', h.google.configured, h.google.configured ? 'Set up' : 'Missing')}
      ${card('Microsoft sign-in', h.microsoft.configured || null, h.microsoft.configured ? 'Set up' : 'Not set up')}
      ${card('Token encryption', h.encryptionKey === 'own key' || null, h.encryptionKey)}
      ${card('Server', true, `up ${mins(h.uptimeMin)}`, `Node ${h.node}`)}
      ${card('Demo users', true, String(h.demoUsers), 'Deleted after a day')}
    </section>
    <section class="box"><p style="margin:0">${problems.length ? `<span class="c-warn">${problems.length} account${problems.length === 1 ? '' : 's'} need${problems.length === 1 ? 's' : ''} attention.</span> <a href="#users" data-act="users-errors">See them on the Users page →</a>` : '<span class="c-ok">Every mailbox connection is working.</span>'}</p></section></div>`;
};

// ── Activity ──────────────────────────────────────────────────
PAGES.activity = async () => {
  const full = can('admin_activity');
  const d = await api(full ? '/admin-activity?limit=300' : '/activity?limit=300');
  const table = (rows) => rows.length ? `<table class="t"><thead><tr><th>When</th><th>Who</th><th>Action</th><th>Detail</th><th>IP</th></tr></thead><tbody>${rows.map(r => `<tr><td class="mono">${time(r.logged_at)}</td><td class="mono ell">${esc(r.admin_email || r.user_email || '')}</td><td class="mono">${esc(r.action)}</td><td>${esc(r.detail)}</td><td class="mono c-muted">${esc(r.ip_address || '')}</td></tr>`).join('')}</tbody></table>` : '<p class="sub">Nothing yet.</p>';
  $('#page').innerHTML = `<div class="wrap"><section class="box tw"><div class="row" style="margin-bottom:10px"><h2 class="h grow" style="margin:0">Everything admins did · newest first</h2>
    <label class="sr" for="aq">Filter</label><input class="in" id="aq" placeholder="Filter" style="max-width:240px">${full ? '<a class="btn sm" href="/admin/api/admin-activity.csv">Download CSV</a>' : ''}</div><div id="aTable">${table(d.logs)}</div></section></div>`;
  $('#aq').addEventListener('input', (e) => { const q = e.target.value.toLowerCase(); $('#aTable').innerHTML = table(d.logs.filter(r => `${r.admin_email} ${r.action} ${r.detail}`.toLowerCase().includes(q))); });
};

// ── Admins ────────────────────────────────────────────────────
PAGES.admins = async () => {
  const [a, acts, og] = await Promise.all([api('/admins'), api('/actions'), can('orgs') ? api('/orgs') : Promise.resolve({ orgs: [] })]);
  const ROLE = { superadmin: 'Super Admin', moderator: 'Moderator', viewer: 'Viewer' };
  $('#page').innerHTML = `<div class="wrap">
    <section class="box"><h1 class="h">Add an admin</h1>
      <form class="row" data-form="new-admin" style="align-items:flex-end">
        <div class="grow" style="max-width:260px"><label class="f" for="na">Email</label><input class="in" id="na" type="email" required></div>
        <div class="grow" style="max-width:200px"><label class="f" for="nn">Name</label><input class="in" id="nn"></div>
        <div class="grow" style="max-width:240px"><label class="f" for="np">Password</label><input class="in" id="np" type="password" minlength="10" required autocomplete="new-password" placeholder="10+ letters and numbers"></div>
        <div><label class="f" for="nr">Role</label><select class="in" id="nr" style="width:auto"><option value="viewer">Viewer</option><option value="moderator">Moderator</option></select></div>
        <div><label class="f" for="no">Sees</label><select class="in" id="no" style="width:auto"><option value="">Everything (Genjutsu team)</option>${og.orgs.length ? og.orgs.map(o => `<option value="${esc(o.org_id)}">Only ${esc(o.name)}</option>`).join('') : '<option disabled>No organizations yet: add one on the Organizations page</option>'}</select></div>
        <button class="btn primary" type="submit">Add admin</button></form>
      <p class="sub" style="margin:10px 0 0">An organization admin sees only that organization's members and threats, at /org. An organization Moderator can also make invite links, remove members and post notices.</p>
</section>
    <section class="grid" style="grid-template-columns:repeat(auto-fit,minmax(260px,1fr))">
      <div><span class="pill c-info">Viewer</span><ul style="margin:10px 0 0;padding-left:18px;line-height:1.8;font-size:13px;color:var(--text2)"><li>Queue, Wall, Threats, Attackers</li><li>Users and honeypot conversations</li><li>Health, reports, system settings (read)</li></ul></div>
      <div><span class="pill c-warn">Moderator</span><ul style="margin:10px 0 0;padding-left:18px;line-height:1.8;font-size:13px;color:var(--text2)"><li>Everything a Viewer has</li><li>Review threats, add notes, change threat levels (user gets the remark)</li><li>Block domains for everyone, post notices</li><li>Mistakes review, scammer details, activity log</li><li>Ask for risky changes (a Super Admin approves)</li></ul></div>
      <div><span class="pill c-danger">Super Admin</span><ul style="margin:10px 0 0;padding-left:18px;line-height:1.8;font-size:13px;color:var(--text2)"><li>Everything a Moderator has</li><li>Add, change, turn off and delete admins</li><li>Suspend and unsuspend users</li><li>Score thresholds, full admin log</li><li>Approve risky changes · cannot be deleted</li></ul></div>
    </section>
    ${acts.pending.length ? `<section class="box"><p style="margin:0"><span class="c-info">${acts.pending.length} change${acts.pending.length === 1 ? '' : 's'} waiting for approval.</span> <a href="#queue">Decide in the Queue →</a></p></section>` : ''}
    <section class="box tw"><h2 class="h">Admins · ${a.admins.length}</h2><table class="t"><thead><tr><th>Admin</th><th>Role</th><th>Sees</th><th>2-step</th><th>Last sign-in</th><th>Status</th><th></th></tr></thead><tbody>
      ${a.admins.map(x => { const sa = x.role === 'superadmin', self = x.email === me.email; return `<tr><td><div>${esc(x.name || '')}</div><div class="mono sub">${esc(x.email)}</div></td>
        <td>${sa || self ? esc(ROLE[x.role] || x.role) : `<label class="sr" for="r-${esc(x.admin_id)}">Role</label><select class="in" id="r-${esc(x.admin_id)}" style="width:auto;height:30px" data-act="role" data-id="${esc(x.admin_id)}">${['viewer', 'moderator'].map(r => `<option value="${r}" ${x.role === r ? 'selected' : ''}>${ROLE[r]}</option>`).join('')}</select>`}</td>
        <td>${x.org_name ? esc(x.org_name) : '<span class="c-muted">Everything</span>'}</td>
        <td>${x.totp_enabled ? '<span class="c-ok">On</span>' : '<span class="c-warn">Off</span>'}</td><td class="mono">${time(x.last_login)}</td>
        <td>${x.is_active ? '<span class="pill c-ok">Active</span>' : '<span class="pill c-muted">Off</span>'}</td>
        <td class="row" style="flex-wrap:nowrap">${!sa && !self ? `<button class="btn sm" type="button" data-act="toggle-admin" data-id="${esc(x.admin_id)}">${x.is_active ? 'Turn off' : 'Turn on'}</button>
          <button class="btn sm ghost-danger" type="button" data-act="delete-admin" data-id="${esc(x.admin_id)}" data-email="${esc(x.email)}">Delete</button>` : ''}
          ${x.totp_enabled && !self ? `<button class="btn sm" type="button" data-act="reset-2fa" data-id="${esc(x.admin_id)}" data-email="${esc(x.email)}">Reset 2-step</button>` : ''}</td></tr>`; }).join('')}
    </tbody></table></section></div>`;
};

// ── Settings ──────────────────────────────────────────────────
PAGES.settings = async () => {
  const [{ settings: s }, ta] = await Promise.all([api('/settings'), api('/team-alerts').catch(() => ({ status: {} }))]);
  const T = ta.status || {};
  const sw = (key, label, desc) => `<label class="switch"><span><b style="font-weight:600">${label}</b><br><span class="sub">${desc}</span></span><input type="checkbox" data-act="setting" data-key="${key}" ${s[key] === 'true' ? 'checked' : ''} ${can('settings') ? '' : 'disabled'}></label>`;
  $('#page').innerHTML = `<div class="wrap"><div class="cols">
    <section class="box"><h1 class="h">Scanning</h1>
      ${sw('scan_on_login', 'Scan when a user signs in', 'Check their inbox straight away')}
      ${sw('honeypot_enabled', 'Honeypot (Nami)', 'Let users reply to scammers with Nami')}
      <div class="switch"><span><b style="font-weight:600">Emails per scan</b><br><span class="sub">How many recent emails to check</span></span>
        <span class="row" style="flex-wrap:nowrap"><label class="sr" for="mx">Emails per scan</label><input class="in mono" id="mx" type="number" min="10" max="200" value="${esc(s.max_emails_scan || 50)}" style="width:90px" ${can('settings') ? '' : 'disabled'}>${can('settings') ? '<button class="btn sm" type="button" data-act="save-max">Save</button>' : ''}</span></div></section>
    <section class="box"><h1 class="h">Team alerts</h1>
      <p class="sub" style="margin:0 0 8px;line-height:1.6">Alerts for the Genjutsu team: new-device admin logins, lockouts, approvals, and dangerous emails found for users (at most ${ta.cap || 20} an hour). Telegram is blocked in Nepal, so these go to Discord and email.</p>
      <div class="switch"><span><b style="font-weight:600">Discord</b><br><span class="sub">${T.discord ? '<span class="c-ok">Connected</span>' : 'Not connected'}</span></span>
        ${can('ml_settings') ? `<form class="row" data-form="team-discord" style="flex-wrap:nowrap"><label class="sr" for="tdw">Discord webhook link</label><input class="in" id="tdw" type="url" placeholder="https://discord.com/api/webhooks/…" style="width:240px"><button class="btn sm" type="submit">${T.discord ? 'Replace' : 'Connect'}</button>${T.discord ? '<button class="btn sm" type="button" data-act="team-discord-off">Remove</button>' : ''}</form>` : ''}</div>
      <div class="switch"><span><b style="font-weight:600">Email</b><br><span class="sub">${T.email ? '<span class="c-ok">Set up</span>' : 'Set SMTP_URL (and TEAM_ALERT_EMAIL) in the server settings'}</span></span></div>
      ${sw('team_alerts', 'Dangerous-email alerts', 'Also send dangerous emails found for users (security alerts always go out)')}
      <div class="row" style="margin-top:8px"><button class="btn sm" type="button" data-act="team-test">Send a test alert</button></div>
    </section>
    <section class="box"><h1 class="h">Score thresholds</h1><p class="sub" style="margin:0 0 6px"><a href="#model">The detection model and its checks are on the Model page →</a></p><p class="sub" style="margin:0 0 6px;line-height:1.6">These change the verdict for every user, so a second admin must approve (unless you are the only Super Admin).</p>
      <div class="switch"><span><b style="font-weight:600">Dangerous from</b></span><span class="row" style="flex-wrap:nowrap"><label class="sr" for="td">Dangerous from</label><input class="in mono" id="td" type="number" min="30" max="100" value="${esc(s.threat_score_dangerous || 60)}" style="width:90px"><button class="btn sm" type="button" data-act="threshold" data-key="threat_score_dangerous" data-input="td">Ask to change</button></span></div>
      <div class="switch"><span><b style="font-weight:600">Suspicious from</b></span><span class="row" style="flex-wrap:nowrap"><label class="sr" for="ts">Suspicious from</label><input class="in mono" id="ts" type="number" min="10" max="59" value="${esc(s.threat_score_suspicious || 30)}" style="width:90px"><button class="btn sm" type="button" data-act="threshold" data-key="threat_score_suspicious" data-input="ts">Ask to change</button></span></div></section>
  </div></div>`;
};

// ── Detection model: learning from real scams ────────────────
PAGES.model = async () => {
  const LAYERS = ['Phishing keywords', 'Suspicious links', 'IP-address links', 'Urgent wording', 'Free-mail sender for a business', 'Too many links', 'SPF / DKIM / DMARC', 'Naive Bayes model', 'Dangerous attachments',
    'Display-name spoofing', 'Look-alike domains', 'Reply-To mismatch', 'Hidden links', 'Payment-fraud wording', 'New domains (RDAP)', 'Global block list'];
  const [d, st, set] = await Promise.all([api('/model'), api('/stats'), api('/settings')]);
  const S = st.stats, th = set.settings;
  const live = d.models.find(m => m.is_active);
  const pct = (x) => x == null ? '—' : Math.round(x * 100) + '%';
  const total = d.sources.reduce((a, x) => a + x.n, 0);
  const STATUS = { active: ['c-ok', 'Live'], rejected: ['c-muted', 'Not better, kept old'], undefined: ['c-muted', ''] };
  $('#page').innerHTML = `<div class="wrap">
    <section class="box"><div class="row" style="align-items:flex-start">
      <div class="grow" style="flex-basis:360px"><h1 class="h">Detection model</h1>
        <h2 style="margin:0 0 6px;font-size:22px">Live: <span class="mono">${esc(d.live)}</span></h2>
        <p style="margin:0;line-height:1.6;color:var(--text2)">The Naive Bayes check learns from real scams. ${d.autoTrain ? 'Every day' : 'When you press Retrain'} it saves new examples we can trust, builds a new model, and tests it on 1 in 5 examples it never saw. It only goes live if it does at least as well as the current one.</p></div>
      ${can('ml_settings') ? '<div class="row"><button class="btn" type="button" data-act="reclassify" title="Re-sort every saved threat into Phishing, Malware, Spoofed sender or Other with the current rules">Re-sort saved threats</button><button class="btn primary" type="button" data-act="model-train">Retrain now</button></div>' : ''}</div>
      ${live?.metrics ? `<section class="grid g4" style="margin-top:16px">
        <div><div class="h" style="margin:0">Accuracy</div><div class="mid mono">${pct(live.metrics.accuracy)}</div><div class="sub">on ${n(live.metrics.tested)} unseen emails</div></div>
        <div><div class="h" style="margin:0">Scams caught</div><div class="mid mono">${pct(live.metrics.recall)}</div><div class="sub">${n(live.metrics.missed)} missed</div></div>
        <div><div class="h" style="margin:0">When it says scam, it's right</div><div class="mid mono">${pct(live.metrics.precision)}</div><div class="sub">${n(live.metrics.falseAlarms)} false alarms</div></div>
        <div><div class="h" style="margin:0">Learned from</div><div class="mid mono">${n(live.samples)}</div><div class="sub">real examples + 40 built-in</div></div></section>`
      : `<p class="sub" style="margin:12px 0 0">Still using the 40 built-in examples. It switches once there are at least 15 real scam and 15 real safe examples and a new model tests better.</p>`}
    </section>
    <div class="cols">
      <section class="box tw"><h2 class="h">Where examples come from · ${n(total)}</h2><table class="t"><thead><tr><th>Source</th><th>Teaches</th><th>Saved</th></tr></thead><tbody>
        ${d.sources.map(x => `<tr><td>${esc(x.note)}</td><td class="lv ${x.label === 'phishing' ? 'dangerous' : x.label === 'safe' ? 'safe' : ''}">${x.label === 'phishing' ? 'scam' : x.label === 'safe' ? 'safe' : 'both'}</td><td class="mono">${n(x.n)}${x.label === 'both' && x.n ? ` <span class="c-muted">(${n(x.scam)} scam, ${n(x.safe)} safe)</span>` : ''}${x.excluded ? ` <span class="c-muted">(${x.excluded} left out)</span>` : ''}</td></tr>`).join('')}</tbody></table>
        <p class="sub" style="margin:10px 0 0;line-height:1.6">Emails users mark "safe" on their own are never used: an admin has to agree first (Mistakes page). Addresses, links, account numbers, wallets and phone numbers are removed before saving.</p></section>
      <section class="box tw"><h2 class="h">Versions</h2>${d.models.length ? `<table class="t"><thead><tr><th>Version</th><th>Made</th><th>Accuracy</th><th>Status</th><th></th></tr></thead><tbody>
        ${d.models.map(m => { const st = m.is_active ? ['c-ok', 'Live'] : (STATUS[m.status] || ['c-muted', m.status || '']); return `<tr><td class="mono">${esc(m.version)}</td><td class="mono">${time(m.created_at)}</td>
          <td class="mono">${pct(m.metrics?.accuracy ?? m.accuracy)}${m.metrics?.previous ? ` <span class="c-muted">vs ${pct(m.metrics.previous.accuracy)}</span>` : ''}</td>
          <td class="${st[0]}">${st[1]}</td><td>${!m.is_active && can('ml_settings') ? `<button class="btn sm" type="button" data-act="model-use" data-id="${esc(m.model_id)}" data-v="${esc(m.version)}">Use this</button>` : ''}</td></tr>`; }).join('')}</tbody></table>` : '<p class="sub">No versions yet.</p>'}</section>
    </div>
    <div class="cols">
      <section class="box"><h2 class="h">Score distribution · all threats</h2>${(() => { const dd = S.dangerousCount || 0, q = S.suspiciousCount || 0, t = Math.max(1, dd + q);
        return `<div style="display:flex;height:10px;margin-bottom:10px"><span style="width:${dd / t * 100}%;background:var(--danger)"></span><span style="width:${q / t * 100}%;background:var(--warn)"></span></div>
        <p class="sub" style="margin:0">Dangerous (score ${esc(th.threat_score_dangerous || 60)}+): ${n(dd)} · Suspicious (${esc(th.threat_score_suspicious || 30)}–${(+th.threat_score_dangerous || 60) - 1}): ${n(q)}. Change the thresholds in Settings.</p>`; })()}</section>
      <section class="box"><h2 class="h">The ${LAYERS.length} checks every email goes through</h2><ol style="margin:0;padding-left:22px;line-height:1.9;font-size:13px;columns:2;column-gap:28px">${LAYERS.map(l => `<li>${l}${l === 'Naive Bayes model' ? ' <span class="c-ok">(learns)</span>' : ''}</li>`).join('')}</ol></section>
    </div>
    <section class="box tw"><h2 class="h">Newest examples</h2>${d.recent.length ? `<table class="t"><thead><tr><th>Added</th><th>Teaches</th><th>Source</th><th>Text (personal details removed)</th><th></th></tr></thead><tbody>
      ${d.recent.map(x => `<tr style="${x.excluded ? 'opacity:.5' : ''}"><td class="mono">${time(x.added_at)}</td><td class="lv ${x.label === 'phishing' ? 'dangerous' : 'safe'}">${x.label === 'phishing' ? 'scam' : 'safe'}</td>
        <td class="mono">${esc(x.source)}</td><td class="ell" style="max-width:520px" title="${esc(x.text)}">${esc(x.text)}</td>
        <td>${can('review') ? `<button class="btn sm" type="button" data-act="sample" data-id="${esc(x.sample_id)}" data-on="${x.excluded ? 'false' : 'true'}">${x.excluded ? 'Put back' : 'Leave out'}</button>` : ''}</td></tr>`).join('')}</tbody></table>
      <p class="sub" style="margin:10px 0 0">If an example has the wrong label, leave it out. The next training ignores it.</p>` : '<p class="sub">No examples saved yet. The first collection runs a few minutes after the server starts.</p>'}</section>
  </div>`;
};

// ── Organizations (organizations) ───────────────────────────────────
// An organization admin sees only their organization. The Super Admin creates organizations and sets the plan.
// There is no member limit: any number of people can join.
const JOINED = { domain: 'Organization email', invite: 'Invite link', list: 'Added by email', admin: 'Added by admin' };
// "People added by email": works for organizations without their own domain (everyone on Gmail)
function allowedHtml(d, orgAttr) {
  const list = d.allowed || [], waiting = list.filter(a => !a.joined).length;
  return `<section class="box tw"><h2 class="h">Added by email · ${list.length}${waiting ? ` <span class="c-muted">(${waiting} not signed in yet)</span>` : ''}</h2>
    <p class="sub" style="margin:0 0 10px;line-height:1.6">For people without an organization email, Gmail included. They join as soon as they sign in to Genjutsu, or right away if they already use it. Nobody else can join this way.</p>
    ${can('org') ? `<form data-form="org-emails" ${orgAttr} style="display:flex;flex-direction:column;gap:8px;margin-bottom:12px">
      <label class="f" for="oe">Email addresses (one per line, or separated by commas)</label>
      <textarea class="in mono" id="oe" rows="3" placeholder="ram.sharma@gmail.com&#10;sita.k@outlook.com" required></textarea>
      <button class="btn primary sm" type="submit" style="align-self:flex-start">Add people</button></form>` : ''}
    ${list.length ? `<table class="t"><thead><tr><th>Email</th><th>Status</th><th>Added</th><th></th></tr></thead><tbody>${list.map(a => `<tr><td class="mono">${esc(a.email)}</td>
      <td>${a.joined ? '<span class="c-ok">Joined</span>' : '<span class="c-muted">Waiting for them to sign in</span>'}</td><td class="mono">${time(a.added_at)}</td>
      <td>${can('org') ? `<button class="btn sm" type="button" data-act="org-email-remove" data-email="${esc(a.email)}" ${orgAttr}>Take off list</button>` : ''}</td></tr>`).join('')}</tbody></table>` : ''}</section>`;
}
function organizationHtml(d, superView) {
  const o = d.org, q = superView ? `data-org="${esc(o.org_id)}"` : '';
  return `<section class="grid g4">
      <div><div class="big">${n(d.seatsUsed)}</div><div class="sub">members · no limit</div></div>
      <div><div class="big">${esc(o.plan_label)}</div><div class="sub">plan</div></div>
      <div><div class="big c-danger">${n(d.members.reduce((a, m) => a + m.threats, 0))}</div><div class="sub">threats caught</div></div>
      <div><div class="big ${o.status === 'active' ? 'c-ok' : 'c-warn'}">${o.status === 'active' ? 'Active' : 'Paused'}</div><div class="sub">status</div></div></section>
    <section class="box"><h2 class="h">How people join</h2><p style="margin:0;line-height:1.7">${o.domains ? `Anyone signing in with an email ending in <b class="mono">${o.domains.split(',').map(x => '@' + esc(x)).join(', ')}</b> joins automatically.` : 'No organization email domain is set, so staff join with an invite link.'} Others can join with an invite link. Public email (Gmail, Outlook, Yahoo…) never joins by itself.</p></section>
    <section class="box tw"><div class="row" style="margin-bottom:10px"><h2 class="h grow" style="margin:0">Invite links · ${d.invites.length}</h2>${can('org') ? `<button class="btn sm primary" type="button" data-act="org-invite" ${q}>New invite link</button>` : ''}</div>
      ${d.invites.length ? `<table class="t"><thead><tr><th>Link</th><th>Used</th><th>Expires</th><th></th></tr></thead><tbody>${d.invites.map(i => `<tr>
        <td class="mono ell" style="max-width:420px">${esc(i.url)}</td><td class="mono">${i.uses} / ${i.max_uses}</td><td class="mono">${time(i.expires_at)}</td>
        <td class="row" style="flex-wrap:nowrap"><button class="btn sm" type="button" data-act="copy" data-text="${esc(i.url)}">Copy</button>${can('org') ? `<button class="btn sm ghost-danger" type="button" data-act="org-revoke" data-code="${esc(i.code)}" ${q}>Stop</button>` : ''}</td></tr>`).join('')}</tbody></table>`
      : '<p class="sub">No invite links. Make one and share it with people who don\'t use the organization email.</p>'}</section>
    ${allowedHtml(d, q)}
    <section class="box tw"><h2 class="h">Members · ${d.members.length}</h2>${d.members.length ? `<table class="t"><thead><tr><th>Email</th><th>Joined by</th><th>Last sign-in</th><th>Last scan</th><th>Threats</th><th></th></tr></thead><tbody>
      ${d.members.map(m => `<tr><td>${can('users') && !me.orgId ? `<a href="#" data-act="member-mails" data-id="${esc(m.user_id)}" data-email="${esc(m.email)}" title="See their emails">${esc(m.email)}</a>` : esc(m.email)}</td><td>${esc(JOINED[m.org_joined] || '—')}</td><td class="mono">${time(m.last_login)}</td><td class="mono">${time(m.last_scan_at)}</td>
        <td class="mono ${m.threats ? 'c-danger' : ''}">${n(m.threats)}</td>
        <td>${can('org') ? `<button class="btn sm ghost-danger" type="button" data-act="org-remove" data-id="${esc(m.user_id)}" data-email="${esc(m.email)}" ${q}>Remove</button>` : ''}</td></tr>`).join('')}</tbody></table>`
      : '<p class="sub">Nobody has joined yet.</p>'}</section>`;
}
let orgPlans = {};
PAGES.orgs = async () => {
  const d = await api('/orgs'); orgPlans = d.plans; PAGES.orgs.rows = d.orgs;
  const sel = location.hash.split('/')[1] || '';
  const planOpts = (v) => Object.entries(d.plans).map(([k, p]) => `<option value="${k}" ${k === v ? 'selected' : ''}>${esc(p.label)}</option>`).join('');
  $('#page').innerHTML = `<div class="wrap">
    <section class="box"><div class="row" style="align-items:flex-end">
      <div class="grow" style="max-width:420px"><label class="f" for="orgPick">Organization</label>
        <select class="in" id="orgPick" data-act="org-pick">${d.orgs.length ? `<option value="">All organizations · ${d.orgs.length}</option>${d.orgs.map(o => `<option value="${esc(o.org_id)}" ${o.org_id === sel ? 'selected' : ''}>${esc(o.name)} · ${n(o.members)} member${o.members === 1 ? '' : 's'}${o.status === 'active' ? '' : ' (paused)'}</option>`).join('')}` : '<option value="">No organizations yet</option>'}</select></div>
      <details class="grow" ${d.orgs.length ? '' : 'open'}><summary class="btn sm" style="display:inline-flex;cursor:pointer">+ Add an organization</summary>
        <form class="row" data-form="new-org" style="align-items:flex-end;margin-top:12px">
          <div class="grow" style="max-width:260px"><label class="f" for="on1">Name</label><input class="in" id="on1" required maxlength="120" placeholder="e.g. Kathmandu Model School, Acme Pvt. Ltd."></div>
          <div class="grow" style="max-width:220px"><label class="f" for="od1">Email domain(s)</label><input class="in mono" id="od1" placeholder="acme.com.np"></div>
          <div><label class="f" for="op1">Plan</label><select class="in" id="op1" style="width:auto">${planOpts('free')}</select></div>
          <button class="btn primary" type="submit">Add</button></form>
        <p class="sub" style="margin:8px 0 0">No payments yet: you set the plan here. There's no member limit.</p></details></div></section>
    <div id="orgBody">${sel ? '<div class="empty">Loading…</div>' : d.orgs.length ? `<section class="box tw"><table class="t"><thead><tr><th>Organization</th><th>Domains</th><th>Plan</th><th>Members</th><th>Admins</th><th>Status</th></tr></thead><tbody>
      ${d.orgs.map(o => `<tr class="click" data-act="org-open" data-org="${esc(o.org_id)}" style="cursor:pointer"><td><a href="#orgs/${esc(o.org_id)}">${esc(o.name)}</a></td><td class="mono ell" style="max-width:220px">${esc(o.domains || '—')}</td><td>${esc(d.plans[o.plan]?.label || o.plan)}</td>
        <td class="mono">${n(o.members)}</td><td class="mono">${n(o.admins)}</td>
        <td>${o.status === 'active' ? '<span class="pill c-ok">Active</span>' : '<span class="pill c-warn">Paused</span>'}</td></tr>`).join('')}</tbody></table></section>`
      : '<div class="empty">Add your first organization above. Then pick it here to see its members and their emails.</div>'}</div></div>`;
  if (sel) $('#orgBody').innerHTML = d.orgs.some(o => o.org_id === sel) ? await orgDetail(sel) : '<div class="err">Organization not found.</div>';
};

// A member's emails: what Genjutsu checked for them (sender, subject, verdict, reasons). Message text is never shown.
async function openMemberMails(id, email) {
  const d = await api(`/users/${encodeURIComponent(id)}/emails?limit=300`);
  const LV = { dangerous: ['c-danger', 'DANGER'], suspicious: ['c-warn', 'SUSPECT'], safe: ['c-ok', 'SAFE'] };
  modal(email, `<p class="sub" style="margin:0">${n(d.total)} email${d.total === 1 ? "" : "s"} checked · ${n(d.counts.dangerous)} dangerous · ${n(d.counts.suspicious)} suspicious · ${n(d.counts.safe)} safe. Newest first. Click a row to see why. Only the Genjutsu team can see this list; organization admins see threats only.</p>
    <div class="chips" role="group" aria-label="Filter" style="margin:4px 0">${[['all', 'All'], ['threats', 'Threats only'], ['safe', 'Safe only']].map(([k, l], i) => `<button class="chip ${i ? '' : 'on'}" type="button" data-act="mail-filter" data-k="${k}">${l}</button>`).join('')}</div>
    ${d.emails.length ? `<table class="t" id="mailTable"><thead><tr><th>When</th><th>Level</th><th>From</th><th>Subject</th><th>Score</th></tr></thead><tbody>${d.emails.map((m, i) => {
      const l = LV[m.level] || ['c-muted', String(m.level || '—').toUpperCase()];
      return `<tr class="click" data-act="mail-why" data-i="${i}" data-level="${esc(m.level)}" style="cursor:pointer"><td class="mono">${time(m.received_at || m.scanned_at)}</td><td class="${l[0]} mono">${l[1]}${m.quarantined ? ' <span class="c-muted">· spam</span>' : ''}</td>
        <td class="mono ell" style="max-width:220px" title="${esc(m.sender_email)}">${esc((m.sender_email || '').replace(/.*</, '').replace(/>.*/, ''))}</td><td class="ell" style="max-width:380px">${esc(m.subject || '(no subject)')}${m.has_attachment ? ' 📎' : ''}</td><td class="mono">${m.score}</td></tr>
        <tr data-why="${i}" data-level="${esc(m.level)}" hidden><td></td><td colspan="4">${(m.reasons || []).length ? `<ul class="reasons" style="margin:0">${m.reasons.map(r => `<li>${esc(r.text || r)}</li>`).join('')}</ul>` : '<span class="sub">No warning signs.</span>'}${m.override ? `<p class="sub" style="margin:6px 0 0">Marked ${esc(m.override)} later${m.override_note ? ': ' + esc(m.override_note) : ''}</p>` : ''}</td></tr>`; }).join('')}</tbody></table>`
      : '<p class="sub">No emails checked yet.</p>'}`, true);
}

// One organization, shown on the Organizations page (#orgs/<id>)
function openOrganization(org) { if (location.hash === '#orgs/' + org) route(); else location.hash = 'orgs/' + org; }
async function orgDetail(org) {
  const q = encodeURIComponent(org);
  const [d, bl, ad] = await Promise.all([api(`/org?org=${q}`), api(`/blocked?org=${q}&limit=50`), api('/admins')]);
  const admins = ad.admins.filter(a => a.org_id === org);
  const ROLE = { moderator: 'Moderator', viewer: 'Viewer' };
  return `<div class="row" style="margin:6px 0 2px"><h2 class="grow" style="margin:0;font-size:20px">${esc(d.org.name)}</h2>
      <a class="btn sm" href="/org/?org=${q}" target="_blank" rel="noopener">Open their portal</a>
      <button class="btn sm" type="button" data-act="org-edit" data-org="${esc(org)}">Edit</button></div>` + organizationHtml(d, true) + `
    <section class="box tw"><h2 class="h">Their admins · ${admins.length}</h2>
      ${admins.length ? `<table class="t"><thead><tr><th>Admin</th><th>Role</th><th>2-step</th><th>Last sign-in</th></tr></thead><tbody>${admins.map(a => `<tr><td><div>${esc(a.name || '')}</div><div class="mono sub">${esc(a.email)}</div></td>
        <td>${esc(ROLE[a.role] || a.role)}${a.is_active ? '' : ' <span class="c-muted">(off)</span>'}</td><td>${a.totp_enabled ? '<span class="c-ok">On</span>' : '<span class="c-warn">Off</span>'}</td><td class="mono">${time(a.last_login)}</td></tr>`).join('')}</tbody></table>`
      : '<p class="sub">No admin yet. Add one below so they can sign in at /org.</p>'}
      ${can('admins') ? `<form class="row" data-form="org-admin" data-org="${esc(org)}" style="align-items:flex-end;margin-top:12px">
        <div class="grow" style="min-width:200px"><label class="f" for="oa-e">Email</label><input class="in" id="oa-e" type="email" required></div>
        <div class="grow" style="min-width:140px"><label class="f" for="oa-n">Name</label><input class="in" id="oa-n"></div>
        <div class="grow" style="min-width:200px"><label class="f" for="oa-p">Password</label><input class="in" id="oa-p" type="password" minlength="10" required autocomplete="new-password" placeholder="10+ letters and numbers"></div>
        <div><label class="f" for="oa-r">Role</label><select class="in" id="oa-r" style="width:auto"><option value="moderator">Moderator: can manage members</option><option value="viewer">Viewer: can only look</option></select></div>
        <button class="btn primary" type="submit">Add admin</button></form>
      <p class="sub" style="margin:8px 0 0">They sign in at <span class="mono">${esc(location.origin)}/org</span> and see only this organization.</p>` : ''}</section>
    <section class="box tw"><h2 class="h">Their threats · latest ${bl.blocked.length}</h2>${bl.blocked.length ? `<table class="t"><thead><tr><th>When</th><th>Level</th><th>From</th><th>Subject</th><th>Sent to</th></tr></thead><tbody>
      ${bl.blocked.map(t => `<tr><td class="mono">${time(t.scannedAt)}</td><td class="lv ${esc(t.threatType)}">${t.threatType === 'dangerous' ? 'DANGER' : 'SUSPECT'}</td>
        <td class="mono ell" style="max-width:200px">${esc((t.senderEmail || '').replace(/.*</, '').replace(/>.*/, ''))}</td><td class="ell" style="max-width:260px">${esc(t.subject || '')}</td><td class="mono ell">${esc(t.userEmail)}</td></tr>`).join('')}</tbody></table>`
      : '<p class="sub">No threats yet.</p>'}</section>`;
}

// ── Your account: password, 2-step login, devices, read-only ──
async function openAccount() {
  const s = await api('/me/security');
  modal('Your account', `
    <section><h3 class="h">2-step login</h3>${s.twoFactor
      ? `<p style="margin:0 0 10px"><span class="c-ok">On.</span> ${s.recoveryLeft} recovery code${s.recoveryLeft === 1 ? '' : 's'} left.</p>
         <form data-form="2fa-off" class="row" style="align-items:flex-end"><div class="grow"><label class="f" for="dp">Password</label><input class="in" id="dp" type="password" required autocomplete="current-password"></div>
         <div style="width:130px"><label class="f" for="dc">Code</label><input class="in mono" id="dc" inputmode="numeric" maxlength="6" required></div><button class="btn ghost-danger" type="submit">Turn off</button></form>`
      : `<p style="margin:0 0 10px;line-height:1.6"><span class="c-warn">Off.</span> With it on, signing in needs your password <i>and</i> a code from your phone.</p><button class="btn primary" type="button" data-act="2fa-setup">Set up 2-step login</button><div id="tfa"></div>`}</section>
    <section><h3 class="h">Change password</h3><form data-form="password" style="display:flex;flex-direction:column;gap:10px">
      <label class="sr" for="pc">Current password</label><input class="in" id="pc" type="password" placeholder="Current password" required autocomplete="current-password">
      <label class="sr" for="pn">New password</label><input class="in" id="pn" type="password" placeholder="New password: 10+ letters and numbers" minlength="10" required autocomplete="new-password">
      <button class="btn" type="submit" style="align-self:flex-start">Change password</button>${s.passwordChangedAt ? `<span class="sub">Last changed ${time(s.passwordChangedAt)}</span>` : ''}</form></section>
    <section><h3 class="h">Read-only mode</h3><label class="switch" style="border:none;padding:0"><span class="sub" style="line-height:1.5">Use this while showing the portal to someone, so nothing gets changed by accident.</span><input type="checkbox" data-act="readonly" ${s.readOnly ? 'checked' : ''}></label></section>
    <section><h3 class="h">Devices you signed in from</h3><table class="t"><tbody>${s.devices.map(d => `<tr><td>${esc(d.label)}</td><td class="mono">${esc(d.ip || '')}</td><td class="mono">${time(d.last_seen)}</td></tr>`).join('')}</tbody></table></section>`);
}

// ============================================================
// ACTIONS (one click handler for the whole page)
// ============================================================
const ACT = {
  'close-modal': () => closeModal(),
  copy: (el) => navigator.clipboard.writeText(el.dataset.text).then(() => toast('Copied.')),
  'org-open': (el) => openOrganization(el.dataset.org),
  async 'org-email-remove'(el) {
    if (!confirm(`Take ${el.dataset.email} off the list? If they already joined, they stay a member (use Remove for that).`)) return;
    await api(`/org/allowed/${encodeURIComponent(el.dataset.email)}${el.dataset.org ? '?org=' + encodeURIComponent(el.dataset.org) : ''}`, { method: 'DELETE' });
    toast('Taken off the list.'); el.dataset.org ? openOrganization(el.dataset.org) : route();
  },
  'org-pick': (el) => { location.hash = el.value ? 'orgs/' + el.value : 'orgs'; },
  'member-mails': (el) => openMemberMails(el.dataset.id, el.dataset.email),
  'mail-why': (el) => { const r = $(`#mailTable tr[data-why="${el.dataset.i}"]`); if (r) r.hidden = !r.hidden; },
  'mail-filter': (el) => {
    const k = el.dataset.k; $$('#modalBody .chip').forEach(c => c.classList.toggle('on', c === el));
    $$('#mailTable tr[data-act="mail-why"]').forEach(r => { const lv = r.dataset.level, show = k === 'all' || (k === 'safe' ? lv === 'safe' : lv !== 'safe'); r.hidden = !show; if (!show) $(`#mailTable tr[data-why="${r.dataset.i}"]`).hidden = true; });
  },
  'org-edit': (el) => {
    const o = (PAGES.orgs.rows || []).find(x => x.org_id === el.dataset.org); if (!o) return;
    modal(`Edit ${o.name}`, `<form data-form="edit-org" data-org="${esc(o.org_id)}" style="display:flex;flex-direction:column;gap:12px">
      <div><label class="f" for="en">Name</label><input class="in" id="en" value="${esc(o.name)}" required maxlength="120"></div>
      <div><label class="f" for="ed">Organization email domain(s), comma separated</label><input class="in mono" id="ed" value="${esc(o.domains)}"></div>
      <div class="row"><div><label class="f" for="ep">Plan</label><select class="in" id="ep" style="width:auto">${Object.entries(orgPlans).map(([k, p]) => `<option value="${k}" ${k === o.plan ? 'selected' : ''}>${esc(p.label)}</option>`).join('')}</select></div>
        <div><label class="f" for="et">Status</label><select class="in" id="et" style="width:auto"><option value="active" ${o.status === 'active' ? 'selected' : ''}>Active</option><option value="suspended" ${o.status !== 'active' ? 'selected' : ''}>Paused</option></select></div></div>
      <p class="sub" style="margin:0">Paused: the organization's admins can't sign in and nobody new joins. Staff keep their own protection.</p>
      <button class="btn primary" type="submit" style="align-self:flex-start">Save</button></form>`);
  },
  async 'org-invite'(el) {
    const r = await post('/org/invites', { org: el.dataset.org });
    await navigator.clipboard.writeText(r.url).catch(() => {});
    toast('Invite link made and copied. It works for 14 days, up to 50 people.');
    el.dataset.org ? openOrganization(el.dataset.org) : route();
  },
  async 'org-revoke'(el) { if (!confirm('Stop this invite link? People who already joined stay.')) return; await api(`/org/invites/${encodeURIComponent(el.dataset.code)}${el.dataset.org ? '?org=' + encodeURIComponent(el.dataset.org) : ''}`, { method: 'DELETE' }); toast('Link stopped.'); el.dataset.org ? openOrganization(el.dataset.org) : route(); },
  async 'org-remove'(el) {
    if (!confirm(`Remove ${el.dataset.email} from the organization? They keep using Genjutsu on their own, and won't rejoin automatically.`)) return;
    await post(`/org/members/${encodeURIComponent(el.dataset.id)}/remove`, { org: el.dataset.org }); toast('Removed.');
    el.dataset.org ? openOrganization(el.dataset.org) : route();
  },
  async reclassify() { const r = await post('/maintenance/reclassify'); toast(`Checked ${r.checked} saved threats, ${r.changed} got a corrected type.`); },
  async 'model-train'(el) { el.textContent = 'Training…'; const r = await post('/model/train'); toast(r.message); route(); },
  async 'model-use'(el) { if (!confirm(`Switch the live model to ${el.dataset.v}? Every new scan uses it straight away.`)) return; await post(`/model/${encodeURIComponent(el.dataset.id)}/activate`); toast(`Now using ${el.dataset.v}.`); route(); },
  async sample(el) { await post(`/model/samples/${encodeURIComponent(el.dataset.id)}/exclude`, { on: el.dataset.on === 'true' }); toast(el.dataset.on === 'true' ? 'Left out of training.' : 'Put back.'); route(); },
  'open-account': () => openAccount(),
  'readonly-off': async () => { await post('/me/readonly', { on: false }); me.readOnly = false; updateBanners(); toast('Read-only mode is off.'); },
  async readonly(el) { const on = el.checked; try { await post('/me/readonly', { on }); me.readOnly = on; updateBanners(); toast(on ? 'Read-only mode is on.' : 'Read-only mode is off.'); } catch (e) { el.checked = !on; throw e; } },
  'q-filter': (el) => { qFilter = el.dataset.k; $$('.chip').forEach(c => c.classList.toggle('on', c.dataset.k === qFilter)); renderQueueList(); },
  'q-open': (el) => { qSel = el.dataset.key; $$('.q').forEach(q => q.classList.toggle('on', q.dataset.key === qSel)); renderQueueDetail(); },
  async 'q-done'(el) { await post('/queue/done', { key: el.dataset.key }); toast('Done.'); qSel = null; route(); },
  async block(el) {
    const d = el.dataset.domain;
    if (!confirm(`Block ${d} for every user? Their emails and links to it will be marked dangerous.`)) return;
    await post('/blocklist', { domain: d, reason: 'Campaign from the queue' });
    if (el.dataset.key) await post('/queue/done', { key: el.dataset.key });
    toast(`${d} is blocked for everyone.`); route();
  },
  async 'feed-rebuild'() { const r = await post('/shared-feed/rebuild'); toast(`Updated: ${r.active} active, ${r.indicators - r.active} watching.`); route(); },
  async 'feed-status'(el) { if (el.dataset.status === 'removed' && !confirm(`Remove ${el.dataset.value} from the shared feed? It won't come back by itself.`)) return; await post(`/shared-feed/${el.dataset.kind}/${el.dataset.status}`, { value: el.dataset.value }); toast('Updated.'); route(); },
  async unblock(el) { if (!confirm(`Remove ${el.dataset.domain} from the block list?`)) return; await api(`/blocklist/${encodeURIComponent(el.dataset.domain)}`, { method: 'DELETE' }); toast('Removed.'); route(); },
  async mistake(el) {
    await post(`/threats/${encodeURIComponent(el.dataset.id)}/review`, { status: el.dataset.status, note: el.dataset.status === 'false_positive' ? 'Admin agrees: false alarm' : 'Admin kept the warning' });
    if (el.dataset.key) await post('/queue/done', { key: el.dataset.key });
    toast('Saved.'); route();
  },
  async decide(el) { await post(`/actions/${encodeURIComponent(el.dataset.id)}/${el.dataset.d}`); toast(el.dataset.d === 'approve' ? 'Approved and done.' : 'Rejected.'); route(); },
  attacker: (el) => { history.replaceState(null, '', `#attackers/${encodeURIComponent(el.dataset.domain)}`); showAttacker(el.dataset.domain); },
  user: (el) => openUser(el.dataset.id),
  async suspend(el) { await post(`/users/${encodeURIComponent(el.dataset.id)}/suspend`, { email: el.dataset.email, reason: $('#sr')?.value || '' }); closeModal(); toast('Suspended.'); route(); },
  async unsuspend(el) { if (!confirm(`Unsuspend ${el.dataset.email}?`)) return; await post(`/users/${encodeURIComponent(el.dataset.id)}/unsuspend`, { email: el.dataset.email }); closeModal(); toast('Unsuspended.'); route(); },
  'users-errors': () => { uFilter = 'problems'; location.hash = 'users'; },
  'u-filter': (el) => { uFilter = el.dataset.k; $$('.chip').forEach(c => c.classList.toggle('on', c.dataset.k === uFilter)); drawUsers(); },
  'hp-filter': (el) => { hpFilter = el.dataset.k; route(); },
  'hp-open': (el, e) => { if (e.target.closest('[data-act="hp-end"]')) return; openHoneypot(el.dataset.id); },
  async 'hp-end'(el) { if (!confirm('End this honeypot conversation? Nami stops replying.')) return; await api(`/honeypot/sessions/${encodeURIComponent(el.dataset.id)}`, { method: 'DELETE' }); toast('Ended.'); route(); },
  why: (el) => {
    const t = el.dataset.src === 'mistakes' ? (PAGES.mistakes.rows || []).find(x => x.email_id === el.dataset.id) : threats.find(x => x.emailId === el.dataset.id);
    if (!t) return;
    const reasons = t.details || [];
    modal(t.subject || '(no subject)', `<p class="mono sub" style="margin:0">${esc(t.senderEmail || t.sender_email)} → ${esc(t.userEmail || t.user_email)}</p>
      ${t.mitre?.length ? `<div>${mitreChips(t.mitre)}</div>` : ''}<section><h3 class="h">Why it was flagged</h3>${reasonsList(reasons)}</section>
      ${t.spf ? `<dl class="kv"><dt>SPF</dt><dd>${esc(t.spf)}</dd><dt>DKIM</dt><dd>${esc(t.dkim || '—')}</dd><dt>DMARC</dt><dd>${esc(t.dmarc || '—')}</dd>${t.country ? `<dt>Sent from</dt><dd>${esc(COUNTRY(t.country))}</dd>` : ''}</dl>` : ''}
      ${t.overrideNote ? `<section><h3 class="h">Admin note</h3><p style="margin:0">${esc(t.overrideNote)}</p></section>` : ''}`);
  },
  review: (el) => {
    const t = threats.find(x => x.emailId === el.dataset.id);
    modal('Review this threat', `<p style="margin:0" class="ell">${esc(t?.subject || '')}</p>
      <form data-form="review" data-id="${esc(el.dataset.id)}" style="display:flex;flex-direction:column;gap:12px">
      <div><label class="f" for="rs">Result</label><select class="in" id="rs"><option value="confirmed">Confirmed threat</option><option value="false_positive">False alarm</option><option value="reviewed">Just reviewed</option></select></div>
      <div><label class="f" for="rn">Note (optional)</label><textarea class="in" id="rn" rows="3" maxlength="500"></textarea></div>
      <button class="btn primary" type="submit" style="align-self:flex-start">Save review</button></form>`);
  },
  override: (el) => {
    const t = threats.find(x => x.emailId === el.dataset.id);
    modal('Change the level', `<p style="margin:0" class="ell">${esc(t?.subject || '')}</p>
      <form data-form="override" data-id="${esc(el.dataset.id)}" data-orig="${esc(t?.threatType || '')}" style="display:flex;flex-direction:column;gap:12px">
      <div><label class="f" for="ol">New level</label><select class="in" id="ol">${['safe', 'suspicious', 'dangerous'].map(l => `<option value="${l}" ${t?.threatType === l ? 'selected' : ''}>${l}</option>`).join('')}</select></div>
      <div><label class="f" for="on">Admin remark: the user gets it as a notification (up to 500 characters)</label><textarea class="in" id="on" rows="3" maxlength="500" placeholder="e.g. We checked this. It's a real email from your bank."></textarea></div>
      <p class="sub" style="margin:0">This change is logged under your name. If you leave the remark empty, the user still gets a short notice about the new level.</p>
      <button class="btn primary" type="submit" style="align-self:flex-start">Save override</button></form>`);
  },
  async 'end-ann'(el) { await api(`/announcements/${encodeURIComponent(el.dataset.id)}`, { method: 'DELETE' }); toast('Notice ended.'); route(); },
  report: () => { const m = $('#rm').value; location.href = `/admin/api/report/monthly?month=${encodeURIComponent(m)}`; },
  async setting(el) { try { await api('/settings', { method: 'PUT', body: { key: el.dataset.key, value: String(el.checked) } }); toast('Saved.'); } catch (e) { el.checked = !el.checked; throw e; } },
  async 'team-test'() { await post('/team-alerts/test'); toast('Test alert sent.'); },
  async 'team-discord-off'() { if (!confirm('Disconnect the team Discord?')) return; await api('/team-alerts/discord', { method: 'PUT', body: { url: '' } }); toast('Disconnected.'); route(); },
  async 'save-max'() { await api('/settings', { method: 'PUT', body: { key: 'max_emails_scan', value: $('#mx').value } }); toast('Saved.'); },
  async threshold(el) { const r = await api('/settings', { method: 'PUT', body: { key: el.dataset.key, value: $('#' + el.dataset.input).value } }); toast(r.message || 'Saved.'); },
  async role(el) { await api(`/admins/${encodeURIComponent(el.dataset.id)}/role`, { method: 'PUT', body: { role: el.value } }); toast('Role changed.'); },
  async 'toggle-admin'(el) { await api(`/admins/${encodeURIComponent(el.dataset.id)}/toggle`, { method: 'PUT' }); toast('Updated.'); route(); },
  async 'delete-admin'(el) { if (!confirm(`Delete ${el.dataset.email}?`)) return; const r = await api(`/admins/${encodeURIComponent(el.dataset.id)}`, { method: 'DELETE' }); toast(r.message || 'Deleted.'); route(); },
  async 'reset-2fa'(el) { if (!confirm(`Turn off 2-step login for ${el.dataset.email}? Do this only if they lost their phone.`)) return; const r = await post('/actions', { action: 'reset_2fa', payload: { adminId: el.dataset.id } }); toast(r.message); route(); },
  async '2fa-setup'(el) {
    const d = await post('/me/2fa/setup');
    el.hidden = true;
    $('#tfa').innerHTML = `<ol style="margin:0 0 12px;padding-left:20px;line-height:1.7"><li>Open an authenticator app on your phone (Google Authenticator, Microsoft Authenticator, Authy).</li><li>Scan this code, or type the key below.</li><li>Enter the 6-digit code it shows.</li></ol>
      <img src="${d.qr}" alt="QR code for your authenticator app" width="180" height="180" style="background:#fff;padding:6px;display:block">
      <p class="mono" style="font-size:13px;word-break:break-all;margin:10px 0">${esc(d.secret.replace(/(.{4})/g, '$1 ').trim())}</p>
      <form data-form="2fa-on" class="row"><label class="sr" for="tc">Code from the app</label><input class="in otp" id="tc" inputmode="numeric" maxlength="6" required style="max-width:200px"><button class="btn primary" type="submit">Turn on</button></form>`;
    $('#tc').focus();
  },
};
document.addEventListener('click', (e) => {
  const el = e.target.closest('[data-act]');
  if (!el || el.tagName === 'SELECT' || (el.type === 'checkbox')) return;
  if (el.tagName === 'A' && !el.getAttribute('href')?.startsWith('#')) return;
  const fn = ACT[el.dataset.act]; if (!fn) return;
  if (el.tagName === 'A') e.preventDefault();
  run(el.tagName === 'BUTTON' ? el : null, () => fn(el, e));
});
document.addEventListener('change', (e) => {
  const el = e.target.closest('select[data-act], input[type=checkbox][data-act]');
  if (el && ACT[el.dataset.act]) run(null, () => ACT[el.dataset.act](el, e));
});
const FORMS = {
  async 'org-emails'(f) {
    const r = await post('/org/allowed', { emails: $('#oe').value, org: f.dataset.org });
    const bits = [r.added.length && `${r.added.length} added`, r.joinedNow.length && `${r.joinedNow.length} joined right away`, r.already.length && `${r.already.length} already on the list`,
      r.otherOrg.length && `${r.otherOrg.length} belong to another organization`, r.invalid.length && `${r.invalid.length} not valid: ${r.invalid.slice(0, 3).join(', ')}`].filter(Boolean);
    toast(bits.join(' · ') || 'Nothing to add.', !r.added.length && !!(r.invalid.length || r.otherOrg.length));
    f.dataset.org ? openOrganization(f.dataset.org) : route();
  },
  async 'org-admin'(f) {
    await post('/admins', { email: $('#oa-e').value.trim(), name: $('#oa-n').value.trim(), password: $('#oa-p').value, role: $('#oa-r').value, orgId: f.dataset.org });
    toast('Admin added. Send them the sign-in link and password, and ask them to turn on 2-step login.'); openOrganization(f.dataset.org);
  },
  async 'new-org'() { await post('/orgs', { name: $('#on1').value, domains: $('#od1').value, plan: $('#op1').value }); toast('Organization added. Now add its admin on the Admins page.'); route(); },
  async 'edit-org'(f) { await api(`/orgs/${encodeURIComponent(f.dataset.org)}`, { method: 'PUT', body: { name: $('#en').value, domains: $('#ed').value, plan: $('#ep').value, status: $('#et').value } }); closeModal(); toast('Saved.'); route(); },
  async block() { const r = await post('/blocklist', { domain: $('#bd').value, reason: $('#br').value }); toast(`${r.domain} is blocked for everyone.`); route(); },
  async 'team-discord'() { await api('/team-alerts/discord', { method: 'PUT', body: { url: $('#tdw').value } }); toast('Team Discord connected.'); route(); },
  async announce() { await post('/announcements', { message: $('#am').value, level: $('#al').value, hours: $('#ah').value }); toast('Notice posted. Users see it on their next page load.'); route(); },
  async review(f) { await post(`/threats/${encodeURIComponent(f.dataset.id)}/review`, { status: $('#rs').value, note: $('#rn').value }); closeModal(); toast('Review saved.'); },
  async override(f) { await api(`/threats/${encodeURIComponent(f.dataset.id)}/override`, { method: 'PATCH', body: { originalLevel: f.dataset.orig, newLevel: $('#ol').value, adminRemark: $('#on').value } }); closeModal(); toast('Level changed. The user was told.'); route(); },
  async 'new-admin'() { await post('/admins', { email: $('#na').value.trim(), name: $('#nn').value.trim(), password: $('#np').value, role: $('#nr').value, orgId: $('#no')?.value || null }); toast('Admin added. Ask them to turn on 2-step login.'); route(); },
  async password() { await post('/me/password', { current: $('#pc').value, next: $('#pn').value }); closeModal(); toast('Password changed.'); },
  async '2fa-on'() {
    const r = await post('/me/2fa/enable', { code: $('#tc').value });
    me.twoFactor = true; updateBanners();
    modal('Save your recovery codes', `<p style="margin:0;line-height:1.6">If you lose your phone, each of these codes lets you sign in once. Save them somewhere safe, like a password manager. <b>They won't be shown again.</b></p>
      <div class="codes">${r.recoveryCodes.map(c => `<span>${esc(c)}</span>`).join('')}</div>
      <div class="row"><button class="btn" type="button" id="copyCodes">Copy</button><button class="btn primary" type="button" data-act="close-modal">I saved them</button></div>`);
    $('#copyCodes').onclick = () => navigator.clipboard.writeText(r.recoveryCodes.join('\n')).then(() => toast('Copied.'));
  },
  async '2fa-off'() { await post('/me/2fa/disable', { password: $('#dp').value, code: $('#dc').value }); me.twoFactor = false; updateBanners(); closeModal(); toast('2-step login is off.'); },
};
document.addEventListener('submit', (e) => {
  const f = e.target.closest('form[data-form]'); if (!f) return;
  e.preventDefault();
  run(e.submitter, () => FORMS[f.dataset.form](f));
});
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !$('#modal').hidden) closeModal(); });
$('#modal').addEventListener('click', (e) => { if (e.target.id === 'modal') closeModal(); });

// ============================================================
// START
// ============================================================
setTheme(document.documentElement.dataset.theme || 'dark');
$$('.theme-toggle').forEach(b => b.addEventListener('click', () => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark')));
$('#meBtn').addEventListener('click', () => run(null, openAccount));
$('#logoutBtn').addEventListener('click', async () => { await fetch('/admin/api/logout', { method: 'POST', credentials: 'include' }); location.hash = ''; showLogin('Signed out.'); });
wireLogin();
fetch('/admin/api/me', { credentials: 'include' }).then(r => r.json()).then(d => { if (d.loggedIn) { me = d.admin; boot(); } else showLogin(); }).catch(() => showLogin('Cannot reach the server.'));
