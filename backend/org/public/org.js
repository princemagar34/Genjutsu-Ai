// Genjutsu — Organization portal: a simple page for an organization's own admins.
// Same sign-in and API as /admin. The server only ever returns this organization's data.
'use strict';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const n = (x) => Number(x || 0).toLocaleString('en-US');
const time = (d) => d ? new Date(d).toLocaleString('en-GB', { timeZone: 'Asia/Kathmandu', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false }) : '—';
const mins = (m) => m >= 60 ? `${Math.floor(m / 60)}h ${m % 60}m` : `${m || 0}m`;
const sender = (s) => String(s || '').replace(/.*</, '').replace(/>.*/, '');
let me = null;
let viewOrg = null;   // Super Admin: which organization they are looking at
const isTeam = () => me && !me.orgId && me.role === 'superadmin';
const can = (p) => !!me?.permissions?.includes(p);

async function api(path, opts = {}) {
  if (viewOrg === 'preview') return window.GJ_PREVIEW(path, (opts.method || 'GET').toUpperCase());   // sample data, nothing sent
  const res = await fetch('/admin/api' + path, { credentials: 'include', ...opts,
    headers: { 'Content-Type': 'application/json', ...(viewOrg ? { 'X-Genjutsu-Org': viewOrg } : {}), ...(opts.headers || {}) },
    body: opts.body && typeof opts.body !== 'string' ? JSON.stringify(opts.body) : opts.body });
  let data = {}; try { data = await res.json(); } catch (_) {}
  if (res.status === 401 && data.expired) { showLogin(data.error); throw new Error(data.error); }
  if (!res.ok || data.success === false) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}
const post = (p, body) => api(p, { method: 'POST', body: body || {} });
function toast(msg, bad = false) { const t = $('#toast'); t.textContent = msg; t.className = 'toast' + (bad ? ' bad' : ''); t.hidden = false; clearTimeout(toast._t); toast._t = setTimeout(() => { t.hidden = true; }, 4200); }
function modal(title, html) { $('#modal > div').style.maxWidth = 'min(1000px, 96vw)'; $('#modal > div').style.width = 'min(1000px, 96vw)'; $('#modalTitle').textContent = title; $('#modalBody').innerHTML = html; $('#modal').hidden = false; }
const closeModal = () => { $('#modal').hidden = true; };
async function run(btn, fn) { if (btn) btn.disabled = true; try { await fn(); } catch (e) { toast(e.message, true); } finally { if (btn) btn.disabled = false; } }
function setTheme(t) {
  document.documentElement.dataset.theme = t; try { localStorage.setItem('gj-org-theme', t); } catch (_) {}
  $$('.theme-toggle').forEach(b => { b.innerHTML = `<i aria-hidden="true"></i>${t === 'dark' ? 'White' : 'Black'}`; });
}

// ── Sign in ───────────────────────────────────────────────────
let recoveryMode = false;
function showLogin(note) {
  me = null; $('#app').hidden = true; $('#login').hidden = false;
  $('#stepPassword').hidden = false; $('#stepCode').hidden = true;
  $('#loginNote').hidden = !note; $('#loginNote').textContent = note || ''; $('#loginErr').hidden = true;
}
function setCodeMode() {
  const lc = $('#lc'); lc.value = '';
  if (recoveryMode) { lc.className = 'in mono'; lc.removeAttribute('maxlength'); lc.removeAttribute('pattern'); lc.inputMode = 'text'; $('#lcLabel').textContent = 'Recovery code'; $('#useRecovery').textContent = 'Use the app code instead'; }
  else { lc.className = 'in otp'; lc.maxLength = 6; lc.pattern = '[0-9]{6}'; lc.inputMode = 'numeric'; $('#lcLabel').textContent = 'Code'; $('#useRecovery').textContent = 'Lost your phone? Use a recovery code'; }
}
function wireLogin() {
  $('#stepPassword').addEventListener('submit', async (e) => {
    e.preventDefault(); const err = $('#loginErr'); err.hidden = true; const btn = e.submitter; btn.disabled = true;
    try {
      const d = await (await fetch('/admin/api/login', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: $('#le').value.trim(), password: $('#lp').value }) })).json();
      if (!d.success) throw new Error(d.error || 'Could not sign in');
      $('#lp').value = '';
      if (d.needs2fa) { recoveryMode = false; setCodeMode(); $('#stepPassword').hidden = true; $('#stepCode').hidden = false; $('#lc').focus(); return; }
      me = d.admin; boot();
    } catch (x) { err.textContent = x.message === 'Failed to fetch' ? 'Cannot reach the server.' : x.message; err.hidden = false; }
    finally { btn.disabled = false; }
  });
  $('#stepCode').addEventListener('submit', async (e) => {
    e.preventDefault(); const err = $('#codeErr'); err.hidden = true; const v = $('#lc').value.trim();
    try {
      const d = await (await fetch('/admin/api/login/2fa', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(recoveryMode ? { recovery: v } : { code: v }) })).json();
      if (!d.success) { if (d.restart) return showLogin(d.error); throw new Error(d.error); }
      $('#lc').value = ''; me = d.admin; boot();
    } catch (x) { err.textContent = x.message; err.hidden = false; }
  });
  $('#useRecovery').addEventListener('click', (e) => { e.preventDefault(); recoveryMode = !recoveryMode; setCodeMode(); });
  $('#backToPw').addEventListener('click', (e) => { e.preventDefault(); showLogin(); });
}

// ── Shell ─────────────────────────────────────────────────────
const TABS = [['overview', 'Overview'], ['threats', 'Threats'], ['members', 'Members'], ['notices', 'Notices']];
async function boot() {
  // Other Genjutsu team admins use the team portal. The Super Admin can look at any organization here.
  if (!me.orgId && !isTeam()) { $('#login').hidden = false; $('#app').hidden = true;
    $('#loginNote').innerHTML = 'You are signed in as a Genjutsu team admin. Use the <a href="/admin/">team portal</a> instead.'; $('#loginNote').hidden = false; return; }
  $('#login').hidden = true; $('#app').hidden = false;
  $('#meBtn').textContent = `${me.name && me.name !== me.roleLabel ? me.name : me.email} · ${me.roleLabel}`;
  if (isTeam()) {
    const { orgs } = await api('/orgs').catch(() => ({ orgs: [] }));
    let pick = new URLSearchParams(location.search).get('org'); try { pick = pick || localStorage.getItem('gj-org-view'); } catch (_) {}
    viewOrg = pick === 'preview' || !orgs.length ? 'preview' : orgs.some(o => o.org_id === pick) ? pick : orgs[0].org_id;
    $('#orgName').innerHTML = `<label class="sr" for="orgSwitch">Organization</label><select class="in" id="orgSwitch" style="height:32px;width:auto;max-width:280px">${orgs.map(o => `<option value="${esc(o.org_id)}" ${o.org_id === viewOrg ? 'selected' : ''}>${esc(o.name)}</option>`).join('')}
      <option value="preview" ${viewOrg === 'preview' ? 'selected' : ''}>Preview (sample data)</option></select>
      <span class="pill c-info" style="margin-left:8px">Genjutsu team view</span>`;
    $('#orgSwitch').onchange = (e) => { viewOrg = e.target.value; try { localStorage.setItem('gj-org-view', viewOrg); } catch (_) {} showPreviewBar(orgs.length); route(); };
    showPreviewBar(orgs.length);
  } else $('#orgName').textContent = me.orgName || 'Your organization';
  document.title = `${me.orgName || 'Organization'} — Genjutsu`;
  $('#tabs').innerHTML = TABS.map(([id, l]) => `<a href="#${id}" class="tab" data-tab="${id}">${l}</a>`).join('');
  $('#roBanner').hidden = !me.readOnly; $('#twoFaBanner').hidden = !!me.twoFactor;
  route();
}
function route() {
  if (!me?.orgId && !viewOrg) return;
  let id = location.hash.replace('#', ''); if (!PAGES[id]) id = 'overview';
  $$('.tab').forEach(a => a.classList.toggle('on', a.dataset.tab === id));
  $('#page').innerHTML = '<div class="empty">Loading…</div>';
  const tok = ++route.tok;   // a slower page finishing late must not cover the current one
  PAGES[id]().catch(e => { if (tok === route.tok) $('#page').innerHTML = `<div class="wrap"><div class="err">${esc(e.message)}</div></div>`; })
    .then(() => {
      if (tok === route.tok) route.drawn = tok;          // the current page is on screen
      else if (route.drawn === route.tok) route();       // an older page just covered it: draw the current one again
    });
}
route.tok = 0;
window.addEventListener('hashchange', route);

const lv = (l) => `<span class="lv ${esc(l)}">${l === 'dangerous' ? 'DANGEROUS' : l === 'suspicious' ? 'SUSPICIOUS' : esc(String(l).toUpperCase())}</span>`;
const trendBars = (t) => {
  if (!t?.labels?.length) return '<p class="sub">No data yet.</p>';
  const max = Math.max(1, ...t.threats.map((x, i) => x + t.safe[i]));
  return `<div style="display:flex;gap:8px;align-items:flex-end;height:120px" role="img" aria-label="Threats and safe emails per day">${t.labels.map((l, i) => `
    <div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;height:100%;justify-content:flex-end">
      <div style="width:100%;display:flex;flex-direction:column;justify-content:flex-end;flex:1">
        <span title="${t.threats[i]} threats" style="display:block;background:var(--danger);height:${t.threats[i] / max * 100}%;min-height:${t.threats[i] ? 2 : 0}px"></span>
        <span title="${t.safe[i]} safe" style="display:block;background:var(--chip);height:${t.safe[i] / max * 100}%"></span></div>
      <span class="mono sub" style="font-size:10px">${esc(String(l).slice(0, 6))}</span></div>`).join('')}</div>
    <p class="sub" style="margin:8px 0 0"><span class="dot c-danger"></span>threats <span class="dot" style="color:var(--chip);margin-left:10px"></span>safe</p>`;
};
const threatRows = (rows) => rows.map(t => `<tr class="click" data-act="why" data-id="${esc(t.emailId)}" tabindex="0">
  <td class="mono">${time(t.scannedAt)}</td><td>${lv(t.threatType)}</td><td class="mono ell" style="max-width:220px">${esc(sender(t.senderEmail))}</td>
  <td class="ell" style="max-width:300px">${esc(t.subject || '(no subject)')}</td><td class="mono ell" style="max-width:200px">${esc(t.userEmail)}</td></tr>`).join('');
const THEAD = '<thead><tr><th>When</th><th>Level</th><th>From</th><th>Subject</th><th>Sent to</th></tr></thead>';

// ── Pages ─────────────────────────────────────────────────────
// The Super Admin's preview: what an organization admin sees, with sample data
function showPreviewBar(haveOrgs) {
  const bar = $('#previewBar'); bar.hidden = viewOrg !== 'preview';
  if (bar.hidden) return;
  bar.innerHTML = `<strong>Preview with sample data.</strong> This is exactly what an organization admin sees. Nothing here is real and nothing can be changed.
    ${haveOrgs ? 'Pick a real organization at the top to see its data.' : `<details style="display:inline-block;margin-left:6px"><summary class="btn sm" style="display:inline-flex;cursor:pointer">Create a real organization</summary>
      <form data-form="first-org" class="row" style="align-items:flex-end;margin-top:10px">
        <div style="width:260px"><label class="f" for="fn">Name</label><input class="in" id="fn" required maxlength="120" placeholder="e.g. Kathmandu Model School"></div>
        <div style="width:240px"><label class="f" for="fd">Its own email domain (optional)</label><input class="in mono" id="fd" placeholder="school.edu.np"></div>
        <button class="btn primary" type="submit">Create</button></form>
      <p class="sub" style="margin:6px 0 0">The domain is the part after @ in the organization's own addresses, like <span class="mono">school.edu.np</span>. Gmail, Outlook and Yahoo can't be used. No domain? Leave it empty.</p></details>`}`;
}

const PAGES = {};
let threats = [];
PAGES.overview = async () => {
  const [st, tr, bl] = await Promise.all([api('/stats'), api('/trend?days=14').catch(() => ({})), api('/blocked?limit=300')]);
  const S = st.stats; threats = bl.blocked;
  $('#page').innerHTML = `<div class="wrap">
    <section class="box"><h1 class="h">Overview</h1><p class="lead">Genjutsu checks every email your members receive and warns them about scams. Here you see what it caught. You never see anyone's normal emails.</p></section>
    <section class="grid g4">
      <div><div class="big">${n(S.totalUsers)}</div><div class="sub">members protected</div></div>
      <div><div class="big">${n(S.totalEmails)}</div><div class="sub">emails checked</div></div>
      <div><div class="big c-danger">${n(S.dangerousCount)}</div><div class="sub">dangerous emails caught</div></div>
      <div><div class="big c-warn">${n(S.suspiciousCount)}</div><div class="sub">suspicious emails</div></div>
    </section>
    <div class="cols">
      <section class="box"><h2 class="h">Last 14 days</h2>${trendBars(tr.trend)}</section>
      <section class="box"><h2 class="h">Scam replies (Nami)</h2><div class="big">${n(S.totalHoneypot)}</div><div class="sub">conversations with scammers · ${mins(S.totalMinutesWasted)} of their time wasted</div></section>
    </div>
    <section class="box tw"><div class="row" style="margin-bottom:10px"><h2 class="h grow" style="margin:0">Latest threats</h2><a class="btn sm" href="#threats">See all</a></div>
      ${threats.length ? `<table class="t">${THEAD}<tbody>${threatRows(threats.slice(0, 6))}</tbody></table>` : '<p class="sub">Nothing caught yet. That\'s good news.</p>'}</section></div>`;
};
let tFilter = 'all', tSearch = '';
PAGES.threats = async () => {
  const bl = await api('/blocked?limit=500'); threats = bl.blocked;
  $('#page').innerHTML = `<div class="wrap"><section class="box tw">
    <div class="row" style="margin-bottom:12px"><h1 class="h grow" style="margin:0">Threats sent to your members · ${n(threats.length)}</h1>
      <div class="chips" role="group" aria-label="Filter">${[['all', 'All'], ['dangerous', 'Dangerous'], ['suspicious', 'Suspicious']].map(([k, l]) => `<button class="chip ${tFilter === k ? 'on' : ''}" type="button" data-act="t-filter" data-k="${k}">${l}</button>`).join('')}</div>
      <label class="sr" for="ts">Search</label><input class="in search" id="ts" placeholder="Search sender, subject, member" value="${esc(tSearch)}"></div>
    <div id="tList"></div><p class="sub" style="margin:10px 0 0">Click a row to see why it was flagged.</p></section></div>`;
  $('#ts').addEventListener('input', (e) => { tSearch = e.target.value; drawThreats(); });
  drawThreats();
};
function drawThreats() {
  const q = tSearch.toLowerCase();
  const rows = threats.filter(t => (tFilter === 'all' || t.threatType === tFilter) && (!q || `${t.senderEmail} ${t.subject} ${t.userEmail}`.toLowerCase().includes(q)));
  $('#tList').innerHTML = rows.length ? `<table class="t">${THEAD}<tbody>${threatRows(rows)}</tbody></table>` : '<div class="empty">Nothing here.</div>';
}
const JOINED = { domain: 'Organization email', invite: 'Invite link', list: 'Added by email', admin: 'Added by admin' };
PAGES.members = async () => {
  const d = await api('/org'); const o = d.org;
  $('#page').innerHTML = `<div class="wrap">
    <section class="box"><h1 class="h">How people join</h1><p class="lead">${o.domains ? `Anyone who signs in to Genjutsu with an email ending in <b class="mono">${o.domains.split(',').map(x => '@' + esc(x)).join(', ')}</b> joins automatically. Others can join with an invite link, or you can add them by email below.` : 'This organization has no email domain of its own, so people join with an invite link, or you add their email addresses below (Gmail works too).'} There's no limit on how many people can join.</p></section>
    <section class="box tw"><div class="row" style="margin-bottom:10px"><h2 class="h grow" style="margin:0">Invite links · ${d.invites.length}</h2>${can('org') ? '<button class="btn sm primary" type="button" data-act="invite">New invite link</button>' : ''}</div>
      ${d.invites.length ? `<table class="t"><thead><tr><th>Link</th><th>Used</th><th>Expires</th><th></th></tr></thead><tbody>${d.invites.map(i => `<tr>
        <td class="mono ell" style="max-width:440px">${esc(i.url)}</td><td class="mono">${i.uses} / ${i.max_uses}</td><td class="mono">${time(i.expires_at)}</td>
        <td class="row" style="flex-wrap:nowrap"><button class="btn sm" type="button" data-act="copy" data-text="${esc(i.url)}">Copy</button>${can('org') ? `<button class="btn sm ghost-danger" type="button" data-act="revoke" data-code="${esc(i.code)}">Stop</button>` : ''}</td></tr>`).join('')}</tbody></table>`
      : '<p class="sub">No invite links yet.</p>'}</section>
    <section class="box tw"><h2 class="h">Added by email · ${n((d.allowed || []).length)}</h2>
      <p class="lead" style="margin:0 0 10px;font-size:14px">For people without an organization email, Gmail included. They join as soon as they sign in to Genjutsu. Nobody else can join this way.</p>
      ${can('org') ? `<form data-form="emails" style="display:flex;flex-direction:column;gap:8px;margin-bottom:12px">
        <label class="f" for="oe">Email addresses (one per line, or separated by commas)</label>
        <textarea class="in mono" id="oe" rows="3" placeholder="ram.sharma@gmail.com&#10;sita.k@outlook.com" required></textarea>
        <button class="btn primary sm" type="submit" style="align-self:flex-start">Add people</button></form>` : ''}
      ${(d.allowed || []).length ? `<table class="t"><thead><tr><th>Email</th><th>Status</th><th>Added</th><th></th></tr></thead><tbody>${d.allowed.map(a => `<tr><td class="mono">${esc(a.email)}</td>
        <td>${a.joined ? '<span class="c-ok">Joined</span>' : '<span class="c-muted">Waiting for them to sign in</span>'}</td><td class="mono">${time(a.added_at)}</td>
        <td>${can('org') ? `<button class="btn sm" type="button" data-act="email-remove" data-email="${esc(a.email)}">Take off list</button>` : ''}</td></tr>`).join('')}</tbody></table>` : ''}</section>
    <section class="box tw"><h2 class="h">Members · ${n(d.members.length)}</h2>${d.members.length ? `<table class="t"><thead><tr><th>Email</th><th>Joined by</th><th>Last sign-in</th><th>Last check</th><th>Threats</th><th></th></tr></thead><tbody>
      ${d.members.map(m => `<tr><td><a href="#" data-act="member" data-id="${esc(m.user_id)}" data-email="${esc(m.email)}">${esc(m.email)}</a></td><td>${esc(JOINED[m.org_joined] || '—')}</td><td class="mono">${time(m.last_login)}</td><td class="mono">${time(m.last_scan_at)}</td>
        <td class="mono ${m.threats ? 'c-danger' : ''}">${n(m.threats)}</td>
        <td>${can('org') ? `<button class="btn sm ghost-danger" type="button" data-act="remove" data-id="${esc(m.user_id)}" data-email="${esc(m.email)}">Remove</button>` : ''}</td></tr>`).join('')}</tbody></table>`
      : `<p class="sub">Nobody has joined yet. ${o.domains ? 'Ask people to sign in with the organization email, share an invite link, or add them by email.' : 'Share an invite link, or add them by email above.'}</p>`}</section></div>`;
};
PAGES.notices = async () => {
  const a = await api('/announcements');
  $('#page').innerHTML = `<div class="wrap">
    ${can('announce') ? `<section class="box"><h1 class="h">Send a notice to all members</h1>
      <form data-form="notice" style="display:flex;flex-direction:column;gap:12px;max-width:640px">
        <div><label class="f" for="am">Message (3 to 280 characters)</label><textarea class="in" id="am" rows="3" maxlength="280" required placeholder="e.g. Fake 'salary update' emails are going around. Don't open the attachment."></textarea></div>
        <div class="row"><div><label class="f" for="al">Type</label><select class="in" id="al" style="width:auto"><option value="info">Info</option><option value="warning">Warning</option><option value="critical">Urgent</option></select></div>
          <div><label class="f" for="ah">Show for</label><select class="in" id="ah" style="width:auto"><option value="24">1 day</option><option value="168" selected>1 week</option><option value="720">30 days</option></select></div></div>
        <button class="btn primary" type="submit" style="align-self:flex-start">Send notice</button></form>
      <p class="sub" style="margin:10px 0 0">Members see it as a banner the next time they open Genjutsu.</p></section>` : ''}
    <section class="box tw"><h2 class="h">Your notices</h2>${a.announcements.length ? `<table class="t"><thead><tr><th>Sent</th><th>Message</th><th>Until</th><th></th></tr></thead><tbody>${a.announcements.map(x => {
      const live = x.active && (!x.expires_at || new Date(x.expires_at) > new Date());
      return `<tr style="${live ? '' : 'opacity:.55'}"><td class="mono">${time(x.created_at)}</td><td>${esc(x.message)}</td><td class="mono">${x.expires_at ? time(x.expires_at) : 'No end'}</td>
        <td>${live && can('announce') ? `<button class="btn sm" type="button" data-act="end-notice" data-id="${esc(x.announcement_id)}">End</button>` : live ? '' : '<span class="c-muted">Ended</span>'}</td></tr>`; }).join('')}</tbody></table>` : '<p class="sub">No notices yet.</p>'}</section></div>`;
};

// ── Your account ──────────────────────────────────────────────
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
      <button class="btn" type="submit" style="align-self:flex-start">Change password</button></form></section>
    <section><h3 class="h">Read-only mode</h3><label class="switch" style="border:none;padding:0"><span class="sub" style="line-height:1.5">Use this while showing the page to someone, so nothing gets changed by accident.</span><input type="checkbox" data-act="readonly" ${s.readOnly ? 'checked' : ''}></label></section>`);
}

// ── Actions ───────────────────────────────────────────────────
const ACT = {
  'close-modal': () => closeModal(),
  'open-account': () => openAccount(),
  copy: (el) => navigator.clipboard.writeText(el.dataset.text).then(() => toast('Copied.')),
  async member(el) {
    if (!threats.length) threats = (await api('/blocked?limit=500')).blocked;
    const mine = threats.filter(t => t.userId === el.dataset.id);
    modal(el.dataset.email, `<p class="sub" style="margin:0">${n(mine.length)} threat${mine.length === 1 ? '' : 's'} sent to this member. Their other emails stay private.</p>
      ${mine.length ? `<table class="t">${THEAD}<tbody>${threatRows(mine)}</tbody></table>` : '<p class="sub">Nothing dangerous so far.</p>'}
      ${isTeam() ? `<p style="margin:0"><button class="btn sm" type="button" data-act="all-mails" data-id="${esc(el.dataset.id)}">Genjutsu team: show every checked email</button></p><div id="allMails"></div>` : ''}`);
  },
  async 'all-mails'(el) {
    const d = await api(`/users/${encodeURIComponent(el.dataset.id)}/emails?limit=300`); el.hidden = true;
    $('#allMails').innerHTML = `<p class="sub" style="margin:0 0 6px">${n(d.total)} checked · ${n(d.counts.dangerous)} dangerous · ${n(d.counts.suspicious)} suspicious · ${n(d.counts.safe)} safe. Sender and subject only; message text is never shown.</p>
      <table class="t"><thead><tr><th>When</th><th>Level</th><th>From</th><th>Subject</th></tr></thead><tbody>${d.emails.map(m => `<tr><td class="mono">${time(m.received_at || m.scanned_at)}</td><td>${lv(m.level)}</td><td class="mono ell" style="max-width:200px">${esc(sender(m.sender_email))}</td><td class="ell" style="max-width:320px">${esc(m.subject || '(no subject)')}</td></tr>`).join('')}</tbody></table>`;
  },
  async 'email-remove'(el) {
    if (!confirm(`Take ${el.dataset.email} off the list? If they already joined, they stay a member (use Remove for that).`)) return;
    await api(`/org/allowed/${encodeURIComponent(el.dataset.email)}`, { method: 'DELETE' }); toast('Taken off the list.'); route();
  },
  't-filter': (el) => { tFilter = el.dataset.k; $$('.chip').forEach(c => c.classList.toggle('on', c.dataset.k === tFilter)); drawThreats(); },
  why: (el) => {
    const t = threats.find(x => x.emailId === el.dataset.id); if (!t) return;
    modal(t.subject || '(no subject)', `<p class="mono sub" style="margin:0">${esc(sender(t.senderEmail))} → ${esc(t.userEmail)} · ${time(t.scannedAt)}</p>
      <p style="margin:0">${lv(t.threatType)} <span class="mono sub">score ${t.score}</span></p>
      <section><h3 class="h">Why it was flagged</h3>${t.details.length ? `<ul class="reasons">${t.details.map(x => `<li>${esc(x.text || x)}</li>`).join('')}</ul>` : '<p class="sub">No reasons recorded.</p>'}</section>
      ${t.overrideNote ? `<section><h3 class="h">Note from Genjutsu</h3><p style="margin:0">${esc(t.overrideNote)}</p></section>` : ''}
      <p class="sub" style="margin:0">Genjutsu already warned ${esc(t.userEmail)} about this email.</p>`);
  },
  async invite() { const r = await post('/org/invites'); await navigator.clipboard.writeText(r.url).catch(() => {}); toast('Invite link made and copied. It works for 14 days, up to 50 people.'); route(); },
  async revoke(el) { if (!confirm('Stop this invite link? People who already joined stay.')) return; await api(`/org/invites/${encodeURIComponent(el.dataset.code)}`, { method: 'DELETE' }); toast('Link stopped.'); route(); },
  async remove(el) { if (!confirm(`Remove ${el.dataset.email}? They keep their own Genjutsu protection, and won't rejoin automatically.`)) return; await post(`/org/members/${encodeURIComponent(el.dataset.id)}/remove`); toast('Removed.'); route(); },
  async 'end-notice'(el) { await api(`/announcements/${encodeURIComponent(el.dataset.id)}`, { method: 'DELETE' }); toast('Notice ended.'); route(); },
  'readonly-off': async () => { await post('/me/readonly', { on: false }); me.readOnly = false; $('#roBanner').hidden = true; toast('Read-only mode is off.'); },
  async readonly(el) { const on = el.checked; try { await post('/me/readonly', { on }); me.readOnly = on; $('#roBanner').hidden = !on; toast(on ? 'Read-only mode is on.' : 'Read-only mode is off.'); } catch (e) { el.checked = !on; throw e; } },
  async '2fa-setup'(el) {
    const d = await post('/me/2fa/setup'); el.hidden = true;
    $('#tfa').innerHTML = `<ol style="margin:0 0 12px;padding-left:20px;line-height:1.7"><li>Open an authenticator app on your phone (Google Authenticator, Microsoft Authenticator, Authy).</li><li>Scan this code, or type the key below.</li><li>Enter the 6-digit code it shows.</li></ol>
      <img src="${d.qr}" alt="QR code for your authenticator app" width="180" height="180" style="background:#fff;padding:6px;display:block">
      <p class="mono" style="font-size:13px;word-break:break-all;margin:10px 0">${esc(d.secret.replace(/(.{4})/g, '$1 ').trim())}</p>
      <form data-form="2fa-on" class="row"><label class="sr" for="tc">Code from the app</label><input class="in otp" id="tc" inputmode="numeric" maxlength="6" required style="max-width:200px"><button class="btn primary" type="submit">Turn on</button></form>`;
  },
};
const FORMS = {
  async 'first-org'() {
    const was = viewOrg; viewOrg = null;   // creating a real organization is a real change, not part of the preview
    let r; try { r = await post('/orgs', { name: $('#fn').value, domains: $('#fd').value, plan: 'free' }); } finally { if (!r) viewOrg = was; }
    try { localStorage.setItem('gj-org-view', r.orgId); } catch (_) {}
    toast('Organization created.'); boot();
  },
  async emails() {
    const r = await post('/org/allowed', { emails: $('#oe').value });
    const bits = [r.added.length && `${r.added.length} added`, r.joinedNow.length && `${r.joinedNow.length} joined right away`, r.already.length && `${r.already.length} already on the list`,
      r.otherOrg.length && `${r.otherOrg.length} belong to another organization`, r.invalid.length && `${r.invalid.length} not valid: ${r.invalid.slice(0, 3).join(', ')}`].filter(Boolean);
    toast(bits.join(' · ') || 'Nothing to add.', !r.added.length && !!(r.invalid.length || r.otherOrg.length)); route();
  },
  async notice() { await post('/announcements', { message: $('#am').value, level: $('#al').value, hours: $('#ah').value }); toast('Notice sent.'); route(); },
  async password() { await post('/me/password', { current: $('#pc').value, next: $('#pn').value }); closeModal(); toast('Password changed.'); },
  async '2fa-on'() {
    const r = await post('/me/2fa/enable', { code: $('#tc').value }); me.twoFactor = true; $('#twoFaBanner').hidden = true;
    modal('Save your recovery codes', `<p style="margin:0;line-height:1.6">If you lose your phone, each code lets you sign in once. Save them somewhere safe. <b>They won't be shown again.</b></p>
      <div class="codes">${r.recoveryCodes.map(c => `<span>${esc(c)}</span>`).join('')}</div>
      <div class="row"><button class="btn" type="button" data-act="copy" data-text="${esc(r.recoveryCodes.join('\n'))}">Copy</button><button class="btn primary" type="button" data-act="close-modal">I saved them</button></div>`);
  },
  async '2fa-off'() { await post('/me/2fa/disable', { password: $('#dp').value, code: $('#dc').value }); me.twoFactor = false; $('#twoFaBanner').hidden = false; closeModal(); toast('2-step login is off.'); },
};
document.addEventListener('click', (e) => {
  const el = e.target.closest('[data-act]'); if (!el || el.type === 'checkbox') return;
  const fn = ACT[el.dataset.act]; if (!fn) return;
  if (el.tagName === 'A') e.preventDefault();
  run(el.tagName === 'BUTTON' ? el : null, () => fn(el, e));
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !$('#modal').hidden) closeModal();
  if (e.key === 'Enter' && e.target.matches('tr[data-act]')) e.target.click();
});
document.addEventListener('change', (e) => { const el = e.target.closest('input[type=checkbox][data-act]'); if (el && ACT[el.dataset.act]) run(null, () => ACT[el.dataset.act](el, e)); });
document.addEventListener('submit', (e) => { const f = e.target.closest('form[data-form]'); if (!f) return; e.preventDefault(); run(e.submitter, () => FORMS[f.dataset.form](f)); });
$('#modal').addEventListener('click', (e) => { if (e.target.id === 'modal') closeModal(); });

setTheme(document.documentElement.dataset.theme || 'light');
$$('.theme-toggle').forEach(b => b.addEventListener('click', () => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark')));
$('#meBtn').addEventListener('click', () => run(null, openAccount));
$('#logoutBtn').addEventListener('click', async () => { await fetch('/admin/api/logout', { method: 'POST', credentials: 'include' }); location.hash = ''; showLogin('Signed out.'); });
wireLogin();
fetch('/admin/api/me', { credentials: 'include' }).then(r => r.json()).then(d => { if (d.loggedIn) { me = d.admin; boot(); } else showLogin(); }).catch(() => showLogin('Cannot reach the server.'));
