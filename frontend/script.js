// ============================================================
// script.js — Genjutsu Frontend Logic (fully integrated with backend)
// ============================================================

// ── Backend API base URL ──────────────────────────────────────
// Production: '' — genjutsu.org's Cloudflare Worker proxies /auth and /api to the backend.
// Local dev: if this page is served by something else on localhost (e.g. VS Code
// Live Server on :5500), talk to the backend on :3001 directly.
const API_BASE = (['localhost', '127.0.0.1'].includes(location.hostname) && location.port !== '3001')
    ? 'http://localhost:3001'
    : '';

// ── Session ID management (cross-domain cookie workaround) ────
function getSessionId() { return localStorage.getItem('genjutsu_sid') || ''; }
function setSessionId(sid) { if (sid) localStorage.setItem('genjutsu_sid', sid); }

// ── Fetch wrapper that always sends session ID header ─────────
async function apiFetch(url, options = {}) {
  const sid = getSessionId();
  const headers = { ...(options.headers || {}) };
  if (sid) headers['x-session-id'] = sid;
  return fetch(url, { ...options, credentials: 'include', headers });
}
// ── Date formatter — always shows in Nepal time (Asia/Kathmandu) ─
function formatDate(dateStr, includeDate = true) {
  if (!dateStr) return '';
  const d = new Date(dateStr);
  if (isNaN(d)) return dateStr;
  return d.toLocaleString('en-GB', {
    timeZone: 'Asia/Kathmandu',
    ...(includeDate ? { day: '2-digit', month: 'short', year: 'numeric' } : {}),
    hour:   '2-digit',
    minute: '2-digit',
    hour12: false
  });
}

// ── Chart instances (so we can update them later) ────────────
let threatLineChart = null;
let threatPieChart  = null;
let checksChart = null, domainsChart = null;

// ── Current loaded emails cache ──────────────────────────────
let cachedEmails = [];
let mailboxSearch = null;   // the query while showing whole-mailbox search results, else null
// FIX: Safe lookup map so onclick handlers never embed raw email data in HTML attributes
// (email.from / email.subject can contain quotes and angle brackets that break onclick)
const emailDataMap = {};

// ── Track active filter so Scan Now and other reloads respect it ──
let currentFilter = 'all';

const knownEmailIds = new Set();
let soundAlertsReady = false;
let soundAlertsEnabled = true;  // mirrors the Sound Alerts toggle in settings

function playNewMailSound() {
    try {
        const ctx = new (window.AudioContext || window.webkitAudioContext)();
        // Happy jingle — C4 → E4 → G4 → C5 ascending mini melody
        [261.63, 329.63, 392.00, 523.25].forEach((freq, i) => {
            const osc  = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.type            = 'sine';
            osc.frequency.value = freq;
            const start = ctx.currentTime + i * 0.12;
            gain.gain.setValueAtTime(0, start);
            gain.gain.linearRampToValueAtTime(0.25, start + 0.02);
            gain.gain.exponentialRampToValueAtTime(0.001, start + 0.25);
            osc.start(start);
            osc.stop(start + 0.25);
        });
    } catch (_) {}
}

// ============================================================
// INIT — runs on every page load
// ============================================================
document.addEventListener('DOMContentLoaded', async () => {
    // Capture session ID from URL after OAuth redirect
    const urlParams = new URLSearchParams(window.location.search);
    const sid = urlParams.get('sid');
    // Invite link (/?join=CODE): remember it through sign-in, then join after the app loads
    const join = urlParams.get('join');
    if (join && /^[A-Za-z0-9_-]{8,64}$/.test(join)) {
        try { localStorage.setItem('gj-join', join); } catch (_) {}
        window.history.replaceState({}, document.title, '/' + location.hash);
    }
    if (sid) {
        setSessionId(sid);
        // Clean URL but keep hash so page is restored after OAuth redirect
        window.history.replaceState({}, document.title, '/' + location.hash);
    }
    initLoginOptions();
    await checkAuthAndInit();
});

// ============================================================
// AUTH — check login, then boot app
// ============================================================
async function checkAuthAndInit() {
    try {
        const res  = await apiFetch(`${API_BASE}/auth/me`);
        const data = await res.json();

        if (!data.loggedIn) {
            showLoginScreen();
            return;
        }

        // Populate user info in sidebar
        document.getElementById('userName').textContent  = data.user.name;
        document.getElementById('userEmail').textContent = data.user.email;
        window.genjutsuProvider = data.user.provider || 'google';
        document.getElementById('gmailConnectedEmail').textContent = data.user.email;
        const inboxLine = document.getElementById('inboxAccountLine');
        if (inboxLine) inboxLine.textContent = `${data.user.email} · ${data.user.providerLabel || 'Gmail'}`;
        const providerLabelEl = document.getElementById('accountProviderLabel');
        if (providerLabelEl) providerLabelEl.textContent = `${data.user.providerLabel || 'Gmail'} · connected`;

        // Set avatar — use Google profile pic if available, else initials
        const avatarEl = document.getElementById('userAvatar');
        if (data.user.picture) {
            avatarEl.innerHTML = `<img src="${data.user.picture}" alt="avatar"
                style="width:100%;height:100%;border-radius:50%;object-fit:cover;">`;
        } else {
            avatarEl.textContent = data.user.name.split(' ').map(n => n[0]).join('').toUpperCase();
        }

        // Show app, hide login
        document.getElementById('loginScreen').style.display = 'none';
        document.getElementById('mainApp').style.display     = 'block';
        // Show AI chat bubble only after login
        const aiBubble = document.getElementById('aiChatBubble');
        if (aiBubble) aiBubble.style.display = 'flex';

        // Boot the rest of the UI
        initNavigation();
        initToast();
        initFilters();
        initHoneypotToggle();
        initSettings();
        initEmailModal();
        initButtons();
        const demoBanner = document.getElementById('demoBanner');
        if (demoBanner) demoBanner.hidden = !data.user.demo;
        window.genjutsuDemo = !!data.user.demo;
        setTimeout(() => startTour(false), 600);
        loadAnnouncements();
        joinPendingOrg().then(loadOrg);

        // Load real data
        await loadDashboard();
        await loadEmails('all');
        await loadThreats();
        await loadHoneypotSessions();

        // Welcome toast
        setTimeout(() => showToast('Welcome to Genjutsu',
            `Inbox protected for ${data.user.name}`, 'success'), 800);

    } catch (err) {
        console.error('Auth check failed:', err);
        showLoginScreen();
    }
}

function showLoginScreen() {
    document.getElementById('loginScreen').style.display = 'flex';
    document.getElementById('mainApp').style.display     = 'none';
}

// ── Login options: Google button + provider bubbles (Outlook, iCloud, Yahoo, More) ──
const IMAP_PROVIDER_INFO = {
    icloud: { title: 'Sign in to iCloud Mail', placeholder: 'you@icloud.com' },
    yahoo:  { title: 'Sign in to Yahoo Mail',  placeholder: 'you@yahoo.com' },
    more:   { title: 'Sign in to another mailbox', placeholder: 'you@example.com' }
};

function initLoginOptions() {
    const demoBtn = document.getElementById('demoLogin');
    if (demoBtn) demoBtn.addEventListener('click', async () => {
        demoBtn.disabled = true;
        demoBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Opening the demo…';
        try {
            const r = await apiFetch(`${API_BASE}/auth/demo`, { method: 'POST' });
            const j = await r.json();
            if (!j.success) throw new Error(j.error || 'Could not start the demo');
            setSessionId(j.sessionId);
            window.location.reload();
        } catch (e) {
            demoBtn.disabled = false;
            demoBtn.innerHTML = '<i class="fas fa-flask"></i> Try a demo with sample emails <span>no sign-in</span>';
            alertLoginError(e.message);
        }
    });
    // OAuth links must reach the backend even when the page is served elsewhere (local dev)
    document.querySelectorAll('[data-auth-path]').forEach(a => {
        a.href = `${API_BASE}${a.getAttribute('data-auth-path')}`;
    });

    const form = document.getElementById('imapLoginForm');
    if (!form) return;
    const select    = document.getElementById('imapProvider');
    const selectRow = document.getElementById('imapProviderField');
    const titleEl   = document.getElementById('imapTitle');
    const emailEl   = document.getElementById('imapEmail');
    const helpEl    = document.getElementById('imapHelp');
    const custom    = document.getElementById('imapCustomFields');
    const errorEl   = document.getElementById('imapError');
    const submit    = document.getElementById('imapSubmit');
    const bubbles   = document.querySelectorAll('[data-imap-provider]');
    let   helpText  = {};

    const showError = (msg) => {
        errorEl.textContent = msg || '';
        errorEl.classList.toggle('visible', Boolean(msg));
    };
    const refreshHelp = () => {
        const isCustom = select.value === 'custom';
        custom.style.display = isCustom ? 'grid' : 'none';
        helpEl.textContent = isCustom
            ? 'Enter the IMAP (incoming) and SMTP (outgoing) servers from your email provider.'
            : (helpText[select.value] ? `Create an app password: ${helpText[select.value]}.` : 'Use an app password from your email provider\'s security settings.');
    };
    const closeForm = () => {
        form.style.display = 'none';
        bubbles.forEach(b => b.classList.remove('active'));
        showError('');
    };

    bubbles.forEach(bubble => bubble.addEventListener('click', () => {
        const choice = bubble.getAttribute('data-imap-provider');
        if (bubble.classList.contains('active')) { closeForm(); return; }
        bubbles.forEach(b => b.classList.toggle('active', b === bubble));
        const info = IMAP_PROVIDER_INFO[choice];
        titleEl.textContent = info.title;
        emailEl.placeholder = info.placeholder;
        if (choice === 'more') {
            selectRow.style.display = 'block';
            if (['icloud', 'yahoo'].includes(select.value)) select.value = 'aol';
        } else {
            selectRow.style.display = 'none';
            select.value = choice;
        }
        showError('');
        refreshHelp();
        form.style.display = 'block';
        emailEl.focus();
    }));
    document.getElementById('imapClose').addEventListener('click', closeForm);
    select.addEventListener('change', refreshHelp);

    // Server-side list carries the app-password instructions for each provider
    fetch(`${API_BASE}/auth/imap/providers`, { credentials: 'include' })
        .then(r => r.json())
        .then(d => { (d.providers || []).forEach(p => { helpText[p.id] = p.help; }); refreshHelp(); })
        .catch(refreshHelp);

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        showError('');
        const body = {
            provider: select.value,
            email:    emailEl.value.trim(),
            password: document.getElementById('imapPassword').value
        };
        if (!body.email || !body.password) return showError('Enter your email address and app password.');
        if (body.provider === 'custom') {
            body.imapHost = document.getElementById('imapHost').value.trim();
            body.imapPort = document.getElementById('imapPort').value;
            body.smtpHost = document.getElementById('smtpHost').value.trim();
            body.smtpPort = document.getElementById('smtpPort').value;
        }
        submit.disabled = true;
        submit.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Connecting to your mailbox...';
        try {
            const res  = await fetch(`${API_BASE}/auth/imap`, {
                method: 'POST', credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            const data = await res.json();
            if (!data.success) throw new Error(data.error || 'Sign-in failed');
            setSessionId(data.sid);
            document.getElementById('imapPassword').value = '';
            window.location.reload();
        } catch (err) {
            showError(err.message === 'Failed to fetch' ? 'Cannot reach the Genjutsu server. Is the backend running?' : err.message);
        } finally {
            submit.disabled = false;
            submit.innerHTML = '<i class="fas fa-sign-in-alt"></i> Sign in';
        }
    });
}

async function logout() {
    await apiFetch(`${API_BASE}/auth/logout`);
    window.location.reload();
}

// ============================================================
// NAVIGATION
// ============================================================
function initNavigation() {
    const navItems  = document.querySelectorAll('.nav-item');
    const pages     = document.querySelectorAll('.page-content');
    const pageTitle = document.querySelector('.page-title');
    const menuToggle = document.querySelector('.menu-toggle');
    const sidebar   = document.querySelector('.sidebar');

    const validPages = ['dashboard','emails','threats','honeypot','settings'];

    // ── Switch to a named page ────────────────────────────────
    function switchPage(pageName, updateHash = true) {
        navItems.forEach(n => n.classList.remove('active'));
        const activeNav = document.querySelector(`.nav-item[data-page="${pageName}"]`);
        if (activeNav) activeNav.classList.add('active');

        pages.forEach(p => p.classList.remove('active'));
        const selectedPage = document.getElementById(`${pageName}-page`);
        if (selectedPage) selectedPage.classList.add('active');

        const label = activeNav?.querySelector('span')?.textContent;
        if (label && pageTitle) pageTitle.textContent = label;

        // Persist in URL hash so refresh restores same page
        if (updateHash) history.replaceState(null, '', '#' + pageName);
        if (pageName === 'settings') { loadSafeSenders(); loadRules(); loadActivity(); loadDiscordStatus(); loadApiKeys(); }
    }

    // ── Restore page from hash on load ────────────────────────
    const hash = location.hash.replace('#', '');
    if (hash && validPages.includes(hash)) {
        switchPage(hash, false);
    }

    // ── Floating nav bubble: the page links live in a card that opens from the bubble ──
    const navOverlay = document.getElementById('sidebarOverlay');
    function setNavOpen(open, returnFocus = false) {
        sidebar.classList.toggle('active', open);
        if (navOverlay) navOverlay.classList.toggle('active', open);
        if (menuToggle) {
            menuToggle.setAttribute('aria-expanded', String(open));
            menuToggle.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
            const icon = menuToggle.querySelector('i');
            if (icon) icon.className = open ? 'fas fa-times' : 'fas fa-bars';
            if (!open && returnFocus) menuToggle.focus();
        }
        if (open) (sidebar.querySelector('.nav-item.active') || sidebar.querySelector('.nav-item'))?.focus();
    }
    const navIsOpen = () => sidebar.classList.contains('active');

    navItems.forEach(item => {
        item.addEventListener('click', function (e) {
            e.preventDefault();
            const pageName = this.dataset.page;
            switchPage(pageName);
            setNavOpen(false);
        });
    });

    if (menuToggle) {
        menuToggle.addEventListener('click', e => {
            e.stopPropagation();
            setNavOpen(!navIsOpen());
        });
    }

    document.addEventListener('click', e => {
        if (navIsOpen() && !sidebar.contains(e.target) && !(menuToggle && menuToggle.contains(e.target))) {
            setNavOpen(false);
        }
    });

    document.addEventListener('keydown', e => {
        if (e.key === 'Escape' && navIsOpen()) setNavOpen(false, true);
    });

    // "View All" threats link
    const viewAll = document.getElementById('viewAllThreats');
    if (viewAll) {
        viewAll.addEventListener('click', e => {
            e.preventDefault();
            document.querySelector('.nav-item[data-page="threats"]').click();
        });
    }

    // Notification bell → threats page
    document.getElementById('notificationBtn')?.addEventListener('click', () => {
        document.querySelector('.nav-item[data-page="threats"]').click();
    });
}

// ============================================================
// TOAST NOTIFICATIONS
// ============================================================
function initToast() {
    const toastClose = document.querySelector('.toast-close');
    toastClose?.addEventListener('click', () =>
        document.getElementById('toast').classList.remove('show'));
}

function showToast(title, message, type = 'danger') {
    const toast    = document.getElementById('toast');
    const iconEl   = toast.querySelector('i');
    const titleEl  = toast.querySelector('h4');
    const msgEl    = toast.querySelector('p');

    const icons = {
        danger:  'fa-shield-alt',
        success: 'fa-check-circle',
        warning: 'fa-exclamation-triangle',
        info:    'fa-info-circle'
    };

    iconEl.className      = `fas ${icons[type] || icons.danger}`;
    iconEl.style.color    = `var(--${type}-color)`;
    toast.style.borderLeftColor = `var(--${type}-color)`;
    titleEl.textContent   = title;
    msgEl.textContent     = message;

    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 5000);
}

// ============================================================
// DASHBOARD — load real data from backend
// ============================================================
// ── Insights: which checks fire most, riskiest domains, response counts ──
async function loadInsights() {
    try {
        const data = await (await apiFetch(`${API_BASE}/api/analytics/insights`)).json();
        if (!data.success) return;
        const r = data.response || {};
        const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
        set('insQuarantined', r.quarantined || 0); set('insBlocked', r.blocked || 0);
        set('insReported', r.reported || 0); set('insHoneypot', `${r.honeypotMinutes || 0} min`);
        const c = themeColors();
        const bar = (canvasId, rows, color, existing) => {
            const el = document.getElementById(canvasId); if (!el) return existing;
            if (existing) existing.destroy();
            if (!rows.length) { el.getContext('2d').clearRect(0, 0, el.width, el.height); return null; }
            return new Chart(el, {
                type: 'bar',
                data: { labels: rows.map(x => x.label), datasets: [{ data: rows.map(x => x.count), backgroundColor: color, borderRadius: 6, maxBarThickness: 22 }] },
                options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: { x: { beginAtZero: true, ticks: { precision: 0, color: c.muted }, grid: { color: c.grid } },
                              y: { ticks: { color: c.text }, grid: { display: false } } } }
            });
        };
        checksChart  = bar('checksChart',  data.checks  || [], '#8b8cff', checksChart);
        domainsChart = bar('domainsChart', data.domains || [], '#ffb547', domainsChart);
    } catch (_) {}
}

// ── Sender profile (shown in the reader and in Investigate) ──
async function senderProfileHtml(from) {
    const addr = ((String(from || '').match(/<([^>]+)>/) || [])[1] || String(from || '')).trim();
    if (!addr.includes('@')) return '';
    try {
        const p = (await (await apiFetch(`${API_BASE}/api/senders/profile?address=${encodeURIComponent(addr)}`)).json()).profile;
        if (!p) return '';
        const earlier = Math.max(0, p.total - 1);
        const line = earlier === 0
            ? '<b>First email from this sender.</b> Be extra careful with unexpected requests.'
            : `<b>${earlier} earlier email${earlier === 1 ? '' : 's'}</b> from this sender since ${formatDate(p.firstSeen, true).split(',')[0]} · ${p.flagged} flagged · average score ${p.avgScore}/100`;
        return `<div class="sender-profile ${earlier === 0 ? 'new' : ''}"><i class="fas fa-user-clock" aria-hidden="true"></i><span>${line}${p.trusted ? ' · <b class="ok-text">Trusted sender</b>' : ''}</span></div>`;
    } catch (_) { return ''; }
}
async function attachSenderProfile(from) {
    const html = await senderProfileHtml(from);
    const host = document.querySelector('#modalBody .reader-head, #modalBody .modal-email-meta');
    if (html && host && !document.querySelector('#modalBody .sender-profile')) host.insertAdjacentHTML('afterend', html);
}

async function loadDashboard() {
    try {
        loadInsights();
        const res  = await apiFetch(`${API_BASE}/api/analytics/dashboard?days=7`);
        const data = await res.json();
        if (!data.success) return;

        // Stat cards
        animateNumber(document.getElementById('statTotal'),   data.stats.totalEmails);
        animateNumber(document.getElementById('statThreats'), (data.stats.dangerous || 0) + (data.stats.suspiciousEmails || 0));
        animateNumber(document.getElementById('statSafe'),    data.stats.safeEmails);

        const pct = data.stats.totalEmails > 0
            ? ((data.stats.safeEmails / data.stats.totalEmails) * 100).toFixed(1)
            : 0;
        document.getElementById('statSafeChange').textContent   = `${pct}% safe rate`;
        document.getElementById('statThreatsChange').textContent =
            `${data.stats.dangerous || 0} dangerous · ${data.stats.suspiciousEmails || 0} suspicious` +
            (data.stats.quarantined ? ` · ${data.stats.quarantined} moved to spam` : '');
        const totalSub = document.getElementById('statTotalChange');
        if (totalSub) totalSub.textContent = `checked in the last ${data.period || '30 days'}`;
        if (data.scanError) showToast('Could not reach your mailbox', 'Showing the emails already checked. ' + data.scanError, 'warning');

        // Refresh both notification badges (threats + remarks)
        loadNotifications();

        // Render charts
        renderLineChart(data.charts.trend);
        renderPieChart(data.charts.types);

        // Recent threats list
        renderRecentThreats(data.recentThreats);

    } catch (err) {
        console.error('Dashboard load error:', err);
        showToast('Connection Error',
            'Could not load dashboard. Is the backend running?', 'warning');
    }
}

function renderRecentThreats(threats) {
    const list = document.getElementById('recentThreatsList');
    if (!threats || threats.length === 0) {
        list.innerHTML = `<div class="empty-state">
            <i class="fas fa-check-circle" style="color:var(--success-color)"></i>
            <p>No threats detected. Your inbox looks clean!</p>
        </div>`;
        return;
    }

    list.innerHTML = threats.map(t => {
        const levelMap = { dangerous: 'high', suspicious: 'medium' };
        const badge    = { dangerous: 'high', suspicious: 'medium' };
        const icon     = t.level === 'dangerous'
            ? 'fa-exclamation-triangle' : 'fa-exclamation-circle';
        const cls      = levelMap[t.level] || 'low';

        return `<div class="threat-item ${cls}">
            <div class="threat-icon"><i class="fas ${icon}"></i></div>
            <div class="threat-details">
                <h4>${escHtml(t.subject)}</h4>
                <p>From: ${escHtml(t.from)}</p>
                <span class="threat-time">${t.reasons ? t.reasons[0] : ''}</span>
            </div>
            <span class="threat-badge ${badge[t.level] || 'low'}">
                ${t.level === 'dangerous' ? 'High Risk' : 'Medium Risk'}
            </span>
        </div>`;
    }).join('');
}

// ── Line chart ────────────────────────────────────────────────
function renderLineChart(trend) {
    const ctx = document.getElementById('threatChart');
    if (!ctx) return;

    if (threatLineChart) threatLineChart.destroy();

    threatLineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: trend.labels,
            datasets: [{
                label: 'Threats (Suspicious + Dangerous)',
                data: trend.data,
                borderColor: '#ef4444',
                backgroundColor: 'rgba(239,68,68,0.1)',
                tension: 0.4,
                fill: true
            }, {
                label: 'Safe Emails',
                // trend.safe comes from getScanHistory via analytics.js — always real DB data
                data: trend.safe && trend.safe.length ? trend.safe : trend.data.map(() => 0),
                borderColor: '#10b981',
                backgroundColor: 'rgba(16,185,129,0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { labels: { color: themeColors().text, font: { size: 12 } } } },
            scales: {
                y: { beginAtZero: true,
                    grid: { color: themeColors().grid }, ticks: { color: themeColors().muted } },
                x: { grid: { color: themeColors().grid }, ticks: { color: themeColors().muted } }
            }
        }
    });
}

// ── Pie chart ─────────────────────────────────────────────────
function renderPieChart(types) {
    const ctx = document.getElementById('pieChart');
    if (!ctx) return;

    if (threatPieChart) threatPieChart.destroy();

    const labels = types.labels.length ? types.labels : ['Phishing','Malware','Spoofing','Other'];
    const data   = types.data.length   ? types.data   : [0, 0, 0, 0];

    threatPieChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels,
            datasets: [{
                data,
                backgroundColor: ['#ef4444','#f59e0b','#3b82f6','#94a3b8'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: themeColors().text, font: { size: 12 }, padding: 15 }
                }
            }
        }
    });
}

// ============================================================
// EMAILS — load and render from backend
// ============================================================
async function loadEmails(filter = 'all', isRetry = false) {
    if (mailboxSearch) { mailboxSearch = null; searchBanner(null); }
    const list = document.getElementById('emailList');
    const countEl = document.getElementById('emailCountInfo');
    list.innerHTML = `<div class="loading-state">
        <i class="fas fa-spinner fa-spin"></i><p>Loading emails...</p></div>`;

    // Blocked tab — separate endpoint, shows emails moved to Gmail spam
    if (filter === 'blocked') {
        try {
            const res  = await apiFetch(`${API_BASE}/api/emails/blocked`);
            const data = await res.json();
            if (!data.success) throw new Error(data.error);
            countEl.textContent = `${data.blocked.length} blocked emails`;
            if (data.blocked.length === 0) {
                list.innerHTML = `<div class="empty-state">
                    <i class="fas fa-ban"></i><p>No blocked emails.</p></div>`;
                return;
            }
            list.innerHTML = data.blocked.map(b => {
                const rawId = b.gmail_msg_id || b.email_id.replace(/^[^-]+-/, '');
                return `<div class="email-item" style="border-left:3px solid #ef4444;opacity:0.75;">
                    <div style="display:flex;align-items:center;gap:12px;padding:14px 16px;">
                        <i class="fas fa-ban" style="color:#ef4444;font-size:18px;flex-shrink:0;"></i>
                        <div style="flex:1;min-width:0;">
                            <div style="font-weight:500;margin-bottom:2px;">${escHtml(b.subject || '(No Subject)')}</div>
                            <div style="font-size:13px;color:var(--text-muted);">From: ${escHtml(b.sender_email || '')}</div>
                            <div style="font-size:11px;color:var(--text-muted);margin-top:2px;">
                                ${b.reason === 'auto' ? 'Quarantined automatically' : 'Blocked'} ${new Date(b.blocked_at).toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'})}
                                &bull; Moved to spam/junk
                            </div>
                        </div>
                        <button onclick="unblockEmail('${escHtml(rawId)}')"
                            style="padding:6px 14px;background:transparent;border:1px solid var(--border-color);border-radius:6px;color:var(--text-muted);font-size:12px;cursor:pointer;white-space:nowrap;flex-shrink:0;">
                            <i class="fas fa-unlock" style="margin-right:4px;"></i>Unblock
                        </button>
                    </div>
                </div>`;
            }).join('');
        } catch (err) {
            list.innerHTML = `<div class="empty-state error"><i class="fas fa-exclamation-circle"></i><p>Could not load blocked emails.</p></div>`;
        }
        return;
    }

    try {
        const res  = await apiFetch(`${API_BASE}/api/emails?filter=${filter}&limit=100`);
        const data = await res.json();
        if (!data.success) throw new Error(data.error);

        cachedEmails = data.emails;
        // Deduplicate by ID on frontend as safety net
        const seenIds = new Set();
        cachedEmails = cachedEmails.filter(e => {
            if (seenIds.has(e.id)) return false;
            seenIds.add(e.id);
            return true;
        });
        // FIX: populate safe lookup map
        cachedEmails.forEach(e => { emailDataMap[e.id] = e; });
        countEl.textContent = `${cachedEmails.length} emails loaded`;
        if (data.quarantined && data.quarantined.length) {
            const n = data.quarantined.length;
            showToast('Quarantined', `${n} dangerous email${n === 1 ? ' was' : 's were'} moved to spam. Open Blocked to undo.`, 'warning');
        }

        // New mail detection
        const newEmails = cachedEmails.filter(e => !knownEmailIds.has(e.id));
        if (soundAlertsReady && soundAlertsEnabled && newEmails.length > 0) {
            playNewMailSound();
            showToast('New Mail', `${newEmails.length} new email${newEmails.length > 1 ? 's' : ''} arrived`, 'info');
        }
        cachedEmails.forEach(e => knownEmailIds.add(e.id));
        if (!soundAlertsReady) soundAlertsReady = true;

        if (data.emails.length === 0) {
            list.innerHTML = `<div class="empty-state">
                <i class="fas fa-inbox"></i><p>No emails found for this filter.</p></div>`;
            return;
        }

        renderEmailList(cachedEmails);

    } catch (err) {
        console.error('Email load error:', err);
        if (!isRetry) {
            // The database may just be waking up: try once more before showing an error
            list.innerHTML = `<div class="loading-state"><i class="fas fa-spinner fa-spin"></i><p>Still connecting… trying again</p></div>`;
            await new Promise(r => setTimeout(r, 2500));
            return loadEmails(filter, true);
        }
        list.innerHTML = `<div class="empty-state error">
            <i class="fas fa-exclamation-circle"></i>
            <p>Could not load emails. <a onclick="loadEmails('all')" href="#">Retry</a></p></div>`;
    }
}

function plainReason(r) {
    const s = String(r || '');
    if (/^display-name spoofing/i.test(s))                return 'Pretends to be a brand';
    if (/^look-alike/i.test(s))                           return 'Fake look-alike address';
    if (/^reply-to mismatch/i.test(s))                    return 'Replies go somewhere else';
    if (/^hidden link/i.test(s))                          return 'Hidden link';
    if (/^payment-fraud/i.test(s))                        return 'Payment fraud wording';
    if (/^payment request/i.test(s))                      return 'Asks for payment';
    if (/^new domain/i.test(s))                           return 'Brand-new website';
    if (/^young domain/i.test(s))                         return 'Recently created website';
    if (/^verified newsletter/i.test(s))                  return 'Newsletter';
    if (/marked this sender as safe/i.test(s))            return 'Trusted sender';
    if (/^known sender/i.test(s))                         return 'Known sender';
    if (/safe ?browsing|malicious url|blacklist/i.test(s)) return 'Known bad link';
    if (/link|url/i.test(s))                              return 'Lots of links';
    if (/urgen|tone|pressure/i.test(s))                   return 'Pushy wording';
    if (/spf|dkim|dmarc|auth|spoof|sender/i.test(s))      return 'Sender not verified';
    if (/attach|file/i.test(s))                           return 'Risky attachment';
    if (/bayes|classifier|ml\b|model/i.test(s))           return 'Looks like phishing';
    if (/keyword|phish/i.test(s))                         return 'Phishing words';
    return s;
}

function renderEmailList(emails) {
    const list = document.getElementById('emailList');
    list.innerHTML = emails.map(email => {
        const t     = email.threat || {};
        // Use override level if admin has set one
        const level = t.overrideLevel || t.level || 'safe';
        const icon  = { safe: 'fa-check-circle', suspicious: 'fa-exclamation-circle',
                        dangerous: 'fa-exclamation-triangle' }[level];
        const tags  = t.reasons?.slice(0, 2).map(r =>
            `<span class="tag">${escHtml(r.split(':')[0])}</span>`).join('') || '';
        const date  = formatDate(email.date, false);

        // Override level tracked but badge not shown in email list
        const overrideLevel = t.overrideLevel || email.overrideLevel || '';
        const overrideBadge = ''; // removed from list view — visible in modal/threats page

        // Friendly wording for the row (the full technical reasons stay in the detail modal)
        const word   = (level === 'safe' && t.category === 'newsletter') ? 'Newsletter' : ({ dangerous: 'Dangerous', suspicious: 'Worth a look', safe: 'Safe' }[level] || 'Safe');
        const rawWhy = (t.reasons && t.reasons[0]) ? String(t.reasons[0]).split(':')[0] : '';
        const plainWhy = level === 'safe' ? 'Nothing unusual' : plainReason(rawWhy);
        const fromName = String(email.from || '').replace(/<.*>/, '').replace(/"/g, '').trim() || String(email.from || '');
        const initial  = (fromName.match(/[A-Za-z0-9]/) || ['?'])[0].toUpperCase();

        const fromAddr = (String(email.from || '').match(/<([^>]+)>/) || [])[1] || '';
        return `<div class="email-item ${level}" data-id="${email.id}">
            <input type="checkbox" class="email-checkbox" aria-label="Select email from ${escHtml(fromName)}">
            <button type="button" class="email-open" onclick="openEmailReader('${email.id}')" title="${escHtml(fromAddr || fromName)}">
                <span class="email-avatar" aria-hidden="true">${escHtml(initial)}</span>
                <span class="email-main">
                    <span class="email-line1">
                        <span class="email-from-name">${escHtml(fromName)}</span>
                        ${t.senderHistory?.firstTime && level !== 'safe' ? '<span class="new-sender" title="You have never received an email from this address before">New sender</span>' : ''}
                        <span class="email-time">${date}</span>
                    </span>
                    <span class="email-subject">${escHtml(email.subject || '(No subject)')}</span>
                    <span class="email-snippet">${escHtml(email.snippet || '')}</span>
                </span>
            </button>
            <div class="email-side">
                <span class="risk-pill ${level}${t.category === 'newsletter' && level === 'safe' ? ' newsletter' : ''}" title="${level === 'safe' ? (t.category === 'newsletter' ? 'Verified newsletter' : 'Nothing unusual') : escHtml(plainWhy)}">${word}</span>
                <button class="btn-icon email-relabel" title="Change threat level" aria-label="Change threat level"
                    onclick="openUserOverrideModal('${email.id}')">
                    <i class="fas fa-edit"></i>
                </button>
            </div>
        </div>`;
    }).join('');

    initSelectAll();
    initSearchFilter();
}

// ============================================================
// USER THREAT LEVEL OVERRIDE MODAL
// ============================================================
function openUserOverrideModal(emailId) {
    const email = emailDataMap[emailId] || cachedEmails.find(e => e.id === emailId);
    if (!email) return;

    const currentLevel = email.threat?.overrideLevel || email.threat?.level || 'suspicious';

    // Create modal if not exists
    let modal = document.getElementById('userOverrideModal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'userOverrideModal';
        modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center;z-index:9999;padding:20px';
        modal.innerHTML = `
            <div style="background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:16px;width:100%;max-width:420px;padding:24px">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
                    <h3 style="font-size:15px;font-weight:600;color:var(--text-primary);display:flex;align-items:center;gap:8px">
                        <i class="fas fa-edit" style="color:#818cf8"></i> Change Threat Level
                    </h3>
                    <button onclick="document.getElementById('userOverrideModal').remove()"
                        style="background:none;border:none;color:var(--text-muted);font-size:18px;cursor:pointer">×</button>
                </div>
                <p id="uomSubject" style="font-size:12px;color:#64748b;margin-bottom:16px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"></p>
                <div style="margin-bottom:14px">
                    <label style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;display:block;margin-bottom:6px">Current Level</label>
                    <span id="uomCurrentLevel" style="display:inline-block;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:600"></span>
                </div>
                <div style="margin-bottom:16px">
                    <label style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;display:block;margin-bottom:6px">New Level</label>
                    <select id="uomNewLevel" style="width:100%;padding:9px 12px;background:var(--bg-primary);border:1px solid var(--border-color);border-radius:8px;color:var(--text-primary);font-size:13px;outline:none">
                        <option value="suspicious">⚠️ Suspicious</option>
                        <option value="dangerous">🚨 Dangerous</option>
                        <option value="safe">✅ Safe (not a threat)</option>
                    </select>
                </div>
                <div style="margin-bottom:16px">
                    <label style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.5px;display:block;margin-bottom:6px">Note (optional)</label>
                    <textarea id="uomNote" rows="2" placeholder="Why are you changing this level?"
                        style="width:100%;padding:9px 12px;background:var(--bg-primary);border:1px solid var(--border-color);border-radius:8px;color:var(--text-primary);font-size:12px;outline:none;resize:vertical;font-family:inherit"></textarea>
                </div>
                <div style="display:flex;gap:10px">
                    <button onclick="document.getElementById('userOverrideModal').remove()"
                        style="flex:1;padding:10px;background:none;border:1px solid var(--border-color);color:var(--text-muted);border-radius:8px;cursor:pointer;font-size:13px">Cancel</button>
                    <button id="uomSaveBtn" onclick="submitUserOverride()"
                        style="flex:1;padding:10px;background:linear-gradient(135deg,#6366f1,#7c3aed);color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:13px;font-weight:600">
                        <i class="fas fa-save"></i> Save
                    </button>
                </div>
            </div>`;
        document.body.appendChild(modal);
        modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
    }

    // Populate
    document.getElementById('uomSubject').textContent = email.subject || '(No Subject)';
    document.getElementById('uomNewLevel').value = currentLevel;

    const levelColors = { dangerous:'#ef4444', suspicious:'#f59e0b', safe:'#10b981' };
    const cur = document.getElementById('uomCurrentLevel');
    cur.textContent = currentLevel;
    cur.style.cssText = `display:inline-block;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:600;background:${levelColors[currentLevel]}22;color:${levelColors[currentLevel]};border:1px solid ${levelColors[currentLevel]}44`;

    // Store emailId for submit
    modal.dataset.emailId = emailId;
    modal.style.display = 'flex';
}

async function submitUserOverride() {
    const modal    = document.getElementById('userOverrideModal');
    const emailId  = modal?.dataset.emailId;
    const newLevel = document.getElementById('uomNewLevel')?.value;
    const note     = document.getElementById('uomNote')?.value?.trim() || '';
    const btn      = document.getElementById('uomSaveBtn');

    if (!emailId || !newLevel) return;

    btn.disabled  = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';

    try {
        const res  = await apiFetch(`${API_BASE}/api/threats/${encodeURIComponent(emailId)}/reclassify`, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ newLevel, note })
        });
        const data = await res.json();

        if (data.success) {
            modal.remove();
            showToast('Level Updated', data.trustedSender ? `Marked safe. Future emails from ${data.trustedSender} will be trusted.` : `Email reclassified as ${newLevel}`, 'success');
            loadSafeSenders();
            // Refresh emails staying in whichever filter is active
            await loadEmails(currentFilter);
            await loadThreats();
            await loadDashboard();
        } else {
            // If not admin, show info message
            btn.disabled  = false;
            btn.innerHTML = '<i class="fas fa-save"></i> Save';
                showToast('Error', data.error || 'Could not update level', 'danger');
        }
    } catch (err) {
        btn.disabled  = false;
        btn.innerHTML = '<i class="fas fa-save"></i> Save';
        showToast('Error', 'Could not connect to server', 'danger');
    }
}

// ============================================================
// THREATS — load from backend
// ============================================================
// Sender, link and attachment checks for a threat card
function threatChecks(email) {
    const t   = email.threat || {};
    const raw = t.authDetails?.raw || '';
    const get = (re) => ((raw.match(re) || [])[1] || 'none').toLowerCase();
    const authState = v => v === 'pass' ? 'pass' : (v === 'fail' || v === 'permerror') ? 'fail' : v === 'softfail' ? 'warn' : 'none';
    const out = [
        ['SPF',   get(/spf=(pass|fail|softfail|neutral|none|permerror)/i)],
        ['DKIM',  get(/dkim=(pass|fail|neutral|none|permerror)/i)],
        ['DMARC', get(/dmarc=(pass|fail|none)/i)]
    ].map(([n, v]) => ({ label: `${n} ${v === 'none' ? '—' : v}`, state: authState(v), title: raw ? `${n}: ${v}` : 'No authentication headers in this email' }));

    const links = email.links || [];
    const BAD = [/paypa1\./i, /g00gle\./i, /amaz0n\./i, /micros0ft\./i, /secure-login\./i, /account-verify\./i, /login-confirm\./i, /verify-account\./i, /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}/];
    const flaggedUrls = new Set((t.iocs && t.iocs.urls) || []);
    const bad = links.filter(u => flaggedUrls.has(u) || BAD.some(p => p.test(u))).length;
    out.push({ label: links.length ? `${links.length} link${links.length === 1 ? '' : 's'}${bad ? ` · ${bad} suspicious` : ''}` : 'No links',
               state: bad ? 'fail' : links.length >= 6 ? 'warn' : links.length ? 'pass' : 'none',
               title: links.length >= 6 && !bad ? 'Many links is common in phishing and in newsletters' : '' });

    const atts = email.attachments || [];
    const risky = atts.filter(a => /\.(exe|bat|cmd|com|msi|ps1|vbs|js|jse|scr|pif|hta|jar|lnk|iso|docm|xlsm|pptm)$/i.test(a.filename || '') || /\.\w{2,4}\.(exe|bat|cmd|scr|vbs|js|pif|com)$/i.test(a.filename || '')).length;
    out.push({ label: atts.length ? `${atts.length} file${atts.length === 1 ? '' : 's'}${risky ? ` · ${risky} risky` : ''}` : 'No files',
               state: risky ? 'fail' : atts.length ? 'pass' : 'none', title: '' });
    return out;
}

async function loadThreats() {
    const detailsEl = document.getElementById('detailedThreats');
    detailsEl.innerHTML = `<div class="loading-state">
        <i class="fas fa-spinner fa-spin"></i><p>Analysing threats...</p></div>`;

    try {
        const res  = await apiFetch(`${API_BASE}/api/threats`);
        const data = await res.json();
        if (!data.success) throw new Error(data.error);

        // Category counts: worked out by the server from every saved scan (quarantined ones included)
        const { summary } = data;
        const types = summary.types || {};
        const total = summary.total || 0;
        const pct = n => total ? `${Math.round((n / total) * 100)}% of threats` : 'none yet';
        [['catPhishing', types.phishing], ['catMalware', types.malware_link], ['catSpoofing', types.spoofed_sender], ['catOther', types.other]]
            .forEach(([id, n]) => {
                document.getElementById(id).textContent = n || 0;
                document.getElementById(id + 'Pct').textContent = pct(n || 0);
            });
        const sub = document.getElementById('threatsSubtitle');
        if (sub) sub.textContent = `Last ${data.days || 90} days · ${summary.scanned || 0} emails checked · ${total} threat${total === 1 ? '' : 's'}` +
            (summary.quarantined ? ` · ${summary.quarantined} moved to spam automatically` : '');

        // Detailed cards
        if (data.threats.length === 0) {
            detailsEl.innerHTML = `<div class="empty-state">
                <i class="fas fa-check-circle" style="color:var(--success-color)"></i>
                <p>No threats found. Your inbox is clean!</p></div>`;
            return;
        }

        // Populate caches so openEmailModal() works from the threats page
        data.threats.forEach(email => {
            emailDataMap[email.id] = email;
            if (!cachedEmails.find(e => e.id === email.id)) cachedEmails.push(email);
        });

        detailsEl.innerHTML = data.threats.map(email => {
            const t     = email.threat;
            const sev   = t.level === 'dangerous' ? 'HIGH RISK' : 'MEDIUM RISK';
            const sevCls = t.level === 'dangerous' ? 'high' : 'medium';

            // Admin override/remark badge
            const overrideRemark = t?.adminRemark || email.adminRemark || '';
            const overrideLevel  = t?.overrideLevel || email.overrideLevel || '';
            const overrideBadge  = overrideLevel ? `
                <div class="admin-override-badge">
                    <i class="fas fa-user-shield"></i>
                    <span>Admin Override: <strong>${escHtml(overrideLevel)}</strong></span>
                </div>` : '';
            const remarkBlock = overrideRemark ? `
                <div class="admin-remark-block">
                    <div class="admin-remark-label"><i class="fas fa-comment-dots"></i> Admin Remark</div>
                    <p class="admin-remark-text">${escHtml(overrideRemark)}</p>
                </div>` : '';

            const word     = t.level === 'dangerous' ? 'Dangerous' : 'Worth a look';
            const score    = Math.max(0, Math.min(100, Number(t.score) || 0));
            const typeName = { phishing: 'Phishing', malware_link: 'Malware', spoofed_sender: 'Spoofed sender', other: 'Other' }[t.subType] || 'Phishing';
            const fromStr  = String(email.from || '');
            const fromName = fromStr.replace(/<.*>/, '').replace(/"/g, '').trim() || fromStr;
            const fromAddr = (fromStr.match(/<([^>]+)>/) || [])[1] || '';
            const checks   = threatChecks(email);

            return `<div class="threat-detail-card tcard ${t.level}" id="threat-${email.id}">
                <div class="tcard-top">
                    <span class="risk-pill ${t.level}">${word}</span>
                    <span class="tcard-type">${typeName}</span>
                    ${overrideBadge}
                    ${email.quarantined ? '<span class="tcard-q" title="Genjutsu moved this to spam automatically"><i class="fas fa-box-archive"></i> In spam</span>' : ''}
                    <time class="threat-date">${formatDate(email.date)}</time>
                </div>
                <h3 class="tcard-subject">${escHtml(email.subject || '(No subject)')}</h3>
                <p class="tcard-from">${escHtml(fromName)}${fromAddr ? ` <span>&lt;${escHtml(fromAddr)}&gt;</span>` : ''}</p>

                <div class="tcard-score" role="img" aria-label="Threat score ${score} out of 100">
                    <div class="tcard-bar"><span style="width:${score}%"></span><i style="left:30%" title="Worth a look from 30"></i><i style="left:60%" title="Dangerous from 60"></i></div>
                    <b>${score}<small>/100</small></b>
                </div>

                <div class="tcard-grid">
                    <div>
                        <div class="tcard-label">Why it was flagged</div>
                        <ul class="tcard-reasons">${(t.reasons || []).map(r => `<li>${escHtml(r)}</li>`).join('') || '<li>No reason recorded</li>'}</ul>
                    </div>
                    <div>
                        <div class="tcard-label">Checks</div>
                        <div class="tcard-checks">${checks.map(c => `<span class="tcheck ${c.state}" title="${escHtml(c.title)}"><span class="dot" aria-hidden="true"></span>${escHtml(c.label)}</span>`).join('')}</div>
                    </div>
                </div>
                ${(t.mitre || []).length ? `<div class="tcard-mitre"><span class="tcard-label">MITRE ATT&amp;CK</span>${t.mitre.map(m => `<a class="mitre-chip" href="${m.url}" target="_blank" rel="noopener noreferrer" title="${escHtml(m.name)}">${m.id} · ${escHtml(m.name)}</a>`).join('')}</div>` : ''}
                ${remarkBlock}
                <div class="threat-actions">
                    <button class="btn btn-secondary"
                        onclick="openEmailModal('${email.id}')"><i class="fas fa-search"></i> Investigate</button>
                    <button class="btn btn-primary"
                        onclick="engageHoneypotById('${email.id}')">
                        <i class="fas fa-bug"></i> Engage Honeypot
                    </button>
                    <button class="btn btn-danger"
                        onclick="blockThreat('${email.id}')">
                        <i class="fas fa-ban"></i> Block Sender
                    </button>
                </div>
            </div>`;
        }).join('');

    } catch (err) {
        console.error('Threats load error:', err);
        detailsEl.innerHTML = `<div class="empty-state error">
            <i class="fas fa-exclamation-circle"></i>
            <p>Could not load threats. Is the backend running?</p></div>`;
    }
}

// ============================================================
// EMAIL DETAIL MODAL
// ============================================================
function initEmailModal() {
    document.getElementById('emailModal')?.addEventListener('click', function (e) {
        if (e.target === this) closeModal();
    });
}

function cleanEmailText(t) {
    return String(t || '')
        .replace(/\r\n?/g, '\n')
        .replace(/[ \t]+\n/g, '\n')
        .replace(/\n{3,}/g, '\n\n')
        .trim()
        .slice(0, 20000);
}

function highlightLinks(text) {
    // Escape first, then wrap URLs in a non-clickable span
    return escHtml(text).replace(/https?:\/\/[^\s<>"')\]]+/g, u => `<span class="mec-link" title="Link (not clickable)">${u}</span>`);
}

// Indicators of compromise for one email, with a copy button
function iocBlock(iocs) {
    if (!iocs) return '';
    const rows = [['Sender addresses', iocs.emails], ['Domains', iocs.domains], ['URLs', iocs.urls], ['IP addresses', iocs.ips], ['Risky files', iocs.attachments]]
        .filter(([, v]) => v && v.length);
    if (!rows.length) return '';
    const plain = rows.map(([k, v]) => `${k}:\n${v.join('\n')}`).join('\n\n');
    return `<div class="modal-iocs">
        <div class="mi-head"><strong>Indicators of compromise</strong>
            <button type="button" class="mec-toggle" onclick="navigator.clipboard.writeText(this.dataset.iocs).then(() => showToast('Copied', 'Indicators copied to the clipboard', 'success'))" data-iocs="${escHtml(plain)}">Copy</button></div>
        ${rows.map(([k, v]) => `<div class="mi-row"><span>${k}</span><div>${v.map(x => `<code>${escHtml(x)}</code>`).join('')}</div></div>`).join('')}
    </div>`;
}

// Download every threat's indicators as CSV or JSON (for a SIEM or a report)
function exportIocs(format) {
    const threats = cachedEmails.filter(e => e.threat && e.threat.level !== 'safe' && e.threat.iocs);
    if (!threats.length) { showToast('Nothing to export', 'No indicators found in the current threats', 'info'); return; }
    let blob, name;
    const stamp = new Date().toISOString().slice(0, 10);
    if (format === 'json') {
        const data = threats.map(e => ({ subject: e.subject, from: e.from, date: e.date, level: e.threat.level, score: e.threat.score,
            type: e.threat.subType, mitre: (e.threat.mitre || []).map(m => m.id), iocs: e.threat.iocs }));
        blob = new Blob([JSON.stringify({ generated: new Date().toISOString(), tool: 'Genjutsu', threats: data }, null, 2)], { type: 'application/json' });
        name = `genjutsu-iocs-${stamp}.json`;
    } else {
        const q = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
        const lines = [['type', 'value', 'email_subject', 'email_from', 'level', 'score', 'mitre'].join(',')];
        threats.forEach(e => {
            const i = e.threat.iocs, m = (e.threat.mitre || []).map(x => x.id).join(' ');
            [['email', i.emails], ['domain', i.domains], ['url', i.urls], ['ip', i.ips], ['file', i.attachments]].forEach(([type, list]) =>
                (list || []).forEach(v => lines.push([type, v, e.subject, e.from, e.threat.level, e.threat.score, m].map(q).join(','))));
        });
        blob = new Blob([lines.join('\n')], { type: 'text/csv' });
        name = `genjutsu-iocs-${stamp}.csv`;
    }
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = name; a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

// ── Trusted senders (Settings) ──
async function loadSafeSenders() {
    const list = document.getElementById('safeSendersList');
    if (!list) return;
    try {
        const data = await (await apiFetch(`${API_BASE}/api/settings/safe-senders`)).json();
        const rows = data.senders || [];
        list.innerHTML = rows.length
            ? rows.map(r => `<li><span>${escHtml(r.sender_email)}</span><button type="button" class="btn-icon" aria-label="Stop trusting ${escHtml(r.sender_email)}" onclick="removeSafeSender('${escHtml(r.sender_email)}')"><i class="fas fa-times"></i></button></li>`).join('')
            : '<li class="empty">No trusted senders yet. Marking an email as safe adds its sender here.</li>';
    } catch (_) { list.innerHTML = '<li class="empty">Could not load trusted senders.</li>'; }
}
async function addSafeSenderFromForm(ev) {
    ev.preventDefault();
    const input = document.getElementById('safeSenderInput');
    const res = await apiFetch(`${API_BASE}/api/settings/safe-senders`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sender: input.value }) });
    const data = await res.json();
    if (data.success) { input.value = ''; showToast('Sender trusted', `${data.sender} won't be flagged unless something is clearly wrong`, 'success'); loadSafeSenders(); }
    else showToast('Could not add', data.error || 'Enter a valid email address', 'warning');
}
async function removeSafeSender(addr) {
    await apiFetch(`${API_BASE}/api/settings/safe-senders/${encodeURIComponent(addr)}`, { method: 'DELETE' });
    showToast('Removed', `${addr} is no longer trusted`, 'info');
    loadSafeSenders();
}

// ── Phase 2: rules, activity, Discord, digest, reporting, delete account ──
const jsonReq = (method, body) => ({ method, headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });

async function loadRules() {
    const list = document.getElementById('rulesList'); if (!list) return;
    try {
        const data = await (await apiFetch(`${API_BASE}/api/account/rules`)).json();
        const label = { trust: 'Trust', flag: 'Worth a look', quarantine: 'Quarantine' };
        list.innerHTML = (data.rules || []).length
            ? data.rules.map(r => `<li><span>When ${escHtml(r.description)} → <b class="rule-${r.action}">${label[r.action]}</b></span><button type="button" class="btn-icon" aria-label="Delete rule" onclick="deleteRule('${escHtml(r.rule_id)}')"><i class="fas fa-times"></i></button></li>`).join('')
            : '<li class="empty">No rules yet. Example: Sender\'s domain is college.edu.np → Trust it.</li>';
    } catch (_) { list.innerHTML = '<li class="empty">Could not load rules.</li>'; }
}
async function addRuleFromForm(ev) {
    ev.preventDefault();
    const body = { field: document.getElementById('ruleField').value, value: document.getElementById('ruleValue').value, action: document.getElementById('ruleAction').value };
    const data = await (await apiFetch(`${API_BASE}/api/account/rules`, jsonReq('POST', body))).json();
    if (data.success) { document.getElementById('ruleValue').value = ''; showToast('Rule added', 'It applies from the next scan', 'success'); loadRules(); }
    else showToast('Could not add rule', data.error || 'Check the value', 'warning');
}
async function deleteRule(id) {
    await apiFetch(`${API_BASE}/api/account/rules/${encodeURIComponent(id)}`, { method: 'DELETE' });
    loadRules();
}
document.addEventListener('change', e => {
    if (e.target && e.target.id === 'ruleField') {
        document.getElementById('ruleValue').placeholder = { domain: 'college.edu.np', sender: 'name@example.com', subject: 'lottery', attachment: 'exe' }[e.target.value];
    }
});

async function loadActivity() {
    const list = document.getElementById('activityList'); if (!list) return;
    try {
        const data = await (await apiFetch(`${API_BASE}/api/account/activity`)).json();
        list.innerHTML = (data.activity || []).length
            ? data.activity.map(a => `<li><time>${formatDate(a.at)}</time><span><b>${escHtml(a.action)}</b>${a.detail ? ` · ${escHtml(a.detail)}` : ''}</span></li>`).join('')
            : '<li class="empty">Nothing yet.</li>';
    } catch (_) { list.innerHTML = '<li class="empty">Could not load activity.</li>'; }
}

async function loadDiscordStatus() {
    const el = document.getElementById('discordStatus'); if (!el) return;
    try {
        const s = (await (await apiFetch(`${API_BASE}/api/settings`)).json()).settings || {};
        el.innerHTML = s.discordConnected ? '<b class="ok-text">Connected.</b>' : '';
    } catch (_) {}
}
async function saveDiscord(ev) {
    ev.preventDefault();
    const url = document.getElementById('discordUrl').value.trim();
    const data = await (await apiFetch(`${API_BASE}/api/account/discord`, jsonReq('PUT', { url }))).json();
    if (data.success) { document.getElementById('discordUrl').value = ''; showToast(url ? 'Discord connected' : 'Discord disconnected', url ? 'Press Test to check it works' : 'Alerts will no longer be sent', 'success'); loadDiscordStatus(); }
    else showToast('Could not save', data.error, 'warning');
}
async function testDiscord() {
    const data = await (await apiFetch(`${API_BASE}/api/account/discord/test`, jsonReq('POST'))).json();
    showToast(data.success ? 'Test sent' : 'Test failed', data.success ? 'Check your Discord channel' : (data.error || 'Could not reach Discord'), data.success ? 'success' : 'danger');
}

async function sendDigestNow(btn) {
    btn.disabled = true; btn.textContent = 'Sending…';
    const data = await (await apiFetch(`${API_BASE}/api/account/digest/send`, jsonReq('POST'))).json();
    btn.disabled = false; btn.textContent = 'Send one now';
    showToast(data.success ? 'Digest sent' : 'Could not send', data.success ? `Check your inbox for "${data.subject}"` : data.error, data.success ? 'success' : 'danger');
}

async function reportPhishing(emailId, subject, btn) {
    if (!confirm('Report this email to the Anti-Phishing Working Group (reportphishing@apwg.org)?\n\nGenjutsu will forward the original email from your account so they can take the fake site down.')) return;
    btn.disabled = true;
    const data = await (await apiFetch(`${API_BASE}/api/account/report-phishing/${encodeURIComponent(emailId)}`, jsonReq('POST', { subject }))).json();
    btn.disabled = false;
    showToast(data.success ? 'Reported' : 'Report failed', data.success ? 'Thanks — the email was forwarded to APWG' : data.error, data.success ? 'success' : 'danger');
}

async function deleteAccount() {
    const typed = prompt('This permanently deletes your Genjutsu account and all its data. It cannot be undone.\n\nType DELETE to confirm:');
    if (typed !== 'DELETE') { if (typed !== null) showToast('Not deleted', 'You need to type DELETE exactly', 'info'); return; }
    const data = await (await apiFetch(`${API_BASE}/api/account`, jsonReq('DELETE', { confirm: 'DELETE' }))).json();
    if (data.success) { alert('Your account and data have been deleted.'); location.href = '/'; }
    else showToast('Could not delete', data.error, 'danger');
}

function openEmailModal(emailId) {
    const email = emailDataMap[emailId] || cachedEmails.find(e => e.id === emailId);
    if (!email) { showToast('Error', 'Email not found — try clicking Scan Now first', 'warning'); return; }

    const modal     = document.getElementById('emailModal');
    modal.querySelector('.modal')?.classList.remove('reading');
    const bodyEl    = document.getElementById('modalBody');
    const subjectEl = document.getElementById('modalSubject');
    const hpBtn     = document.getElementById('modalEngageHoneypot');

    subjectEl.textContent = email.subject;

    const t = email.threat;
    const levelColor = { safe:'var(--success-color)', suspicious:'var(--warning-color)',
                         dangerous:'var(--danger-color)' }[t?.level] || 'var(--text-muted)';

    const modalOverrideRemark = t?.adminRemark || email.adminRemark || '';
    const modalOverrideLevel  = t?.overrideLevel || email.overrideLevel || '';

    bodyEl.innerHTML = `
        <div class="modal-email-meta">
            <div class="modal-meta-row"><strong>From:</strong> ${escHtml(email.from)}</div>
            <div class="modal-meta-row"><strong>To:</strong> ${escHtml(email.to)}</div>
            <div class="modal-meta-row"><strong>Date:</strong> ${formatDate(email.date)}</div>
            <div class="modal-meta-row">
                <strong>Threat Level:</strong>
                <span style="color:${levelColor};font-weight:600;text-transform:capitalize;">
                    ${t?.level || 'safe'} (Score: ${t?.score || 0}/100)
                </span>
                ${modalOverrideLevel ? `<span class="modal-override-chip"><i class="fas fa-user-shield"></i> Overridden to: ${escHtml(modalOverrideLevel)}</span>` : ''}
            </div>
        </div>
        ${modalOverrideRemark ? `
        <div class="modal-admin-remark">
            <div class="modal-admin-remark-label"><i class="fas fa-comment-dots"></i> Admin Remark</div>
            <p>${escHtml(modalOverrideRemark)}</p>
        </div>` : ''}
        ${t?.reasons?.length ? `
        <div class="modal-threats">
            <strong>⚠️ Threat Reasons:</strong>
            <ul>${t.reasons.map(r => `<li>${escHtml(r)}</li>`).join('')}</ul>
        </div>` : ''}
        ${(t?.mitre || []).length ? `
        <div class="modal-mitre">
            <strong>MITRE ATT&amp;CK techniques</strong>
            <div>${t.mitre.map(m => `<a class="mitre-chip" href="${m.url}" target="_blank" rel="noopener noreferrer">${m.id} · ${escHtml(m.name)}</a>`).join('')}</div>
        </div>` : ''}
        ${iocBlock(t?.iocs)}
        ${email.links?.length ? `
        <div class="modal-links">
            <strong>🔗 Links Found (${email.links.length}):</strong>
            <ul>${email.links.slice(0,20).map(l =>
                `<li style="word-break:break-all;font-size:12px;color:var(--warning-color)">${escHtml(l)}</li>`
            ).join('')}</ul>
        </div>` : ''}
        <div class="modal-body-text">
            <strong>Preview:</strong>
            <p>${escHtml(email.snippet)}</p>
        </div>`;

    // ── Full email content, shown as safe plain text ──────────────
    // Links are highlighted but not clickable, and no images or remote content load,
    // so opening a phishing email here can't track or trick the user.
    const fullText = cleanEmailText(email.body || '');
    const contentBox = document.createElement('div');
    contentBox.className = 'modal-email-content';
    contentBox.innerHTML = `
        <div class="mec-head">
            <strong><i class="fas fa-envelope-open-text"></i> Email content</strong>
            ${fullText ? `<button type="button" class="mec-toggle" aria-expanded="false">Show full message</button>` : ''}
        </div>
        <p class="mec-note"><i class="fas fa-shield-alt"></i> Shown as plain text: links can't be clicked and images don't load, so it's safe to read.</p>
        ${fullText
            ? `<div class="mec-text collapsed" tabindex="0">${highlightLinks(fullText)}</div>`
            : `<div class="mec-text empty">This email has no plain-text version, so only the preview is available: <em>${escHtml(email.snippet || '')}</em></div>`}`;
    const metaEl = bodyEl.querySelector('.modal-email-meta');
    metaEl.after(contentBox);
    bodyEl.querySelector('.modal-body-text')?.remove();   // the full content replaces the short preview
    const tgl = contentBox.querySelector('.mec-toggle');
    tgl?.addEventListener('click', () => {
        const box = contentBox.querySelector('.mec-text');
        const open = box.classList.toggle('collapsed') === false;
        tgl.setAttribute('aria-expanded', String(open));
        tgl.textContent = open ? 'Show less' : 'Show full message';
    });

    const reportBtn = document.getElementById('modalReport');
    if (reportBtn) {
        reportBtn.style.display = t?.level !== 'safe' ? 'inline-flex' : 'none';
        reportBtn.onclick = () => reportPhishing(email.id, email.subject, reportBtn);
    }
    // Show honeypot button only for threats
    if (t?.level !== 'safe') {
        hpBtn.style.display = 'inline-flex';
        hpBtn.onclick = () => { closeModal(); engageHoneypot(email.id, email.from, email.subject); };
    } else {
        hpBtn.style.display = 'none';
    }

    // Inject AI summary box
    setTimeout(() => {
        const mb = document.getElementById('modalBody');
        if (mb && !document.getElementById('aiSummaryBox')) {
            const box = document.createElement('div');
            box.className = 'ai-summary-box';
            box.id = 'aiSummaryBox';
            box.innerHTML = `<div class="ai-summary-label"><i class="fas fa-robot"></i> AI Summary</div>
            <div style="display:flex;align-items:center;gap:8px;color:var(--text-muted);font-size:13px">
                <button class="btn-ai-summary" onclick="summariseEmailWithAI('${emailId}')">
                    <i class="fas fa-robot"></i> Generate AI Summary
                </button>
                <span style="font-size:11px">Click to analyse this email with AI</span>
            </div>`;
            mb.insertBefore(box, mb.firstChild);
        }
    }, 50);

    modal.style.display = 'flex';
    attachSenderProfile(email.from);
}

// ── Email reader: just the email, like opening it in a mail app ──
// Used by "View Email" on the Threats page, where the threat details are
// already on the card. Shown as plain text: links can't be clicked and
// no images or remote content load.
function openEmailReader(emailId) {
    const email = emailDataMap[emailId] || cachedEmails.find(e => e.id === emailId);
    if (!email) { showToast('Error', 'Email not found — try clicking Scan Now first', 'warning'); return; }

    const modal  = document.getElementById('emailModal');
    const bodyEl = document.getElementById('modalBody');
    modal.querySelector('.modal')?.classList.add('reading');
    document.getElementById('modalSubject').textContent = email.subject || '(No subject)';
    const hpBtn = document.getElementById('modalEngageHoneypot');
    if (hpBtn) hpBtn.style.display = 'none';
    const rpBtn = document.getElementById('modalReport');
    if (rpBtn) rpBtn.style.display = 'none';

    const from     = String(email.from || '');
    const fromName = from.replace(/<.*>/, '').replace(/"/g, '').trim();
    const fromAddr = (from.match(/<([^>]+)>/) || [])[1] || (fromName.includes('@') ? '' : '');
    const initial  = ((fromName || from).match(/[A-Za-z0-9]/) || ['?'])[0].toUpperCase();
    const text     = cleanEmailText(email.body || '');
    const atts     = email.attachments || [];

    const lvl   = (email.threat?.overrideLevel || email.threat?.level || 'safe');
    const why   = (email.threat?.reasons || [])[0] ? plainReason(String(email.threat.reasons[0]).split(':')[0]) : '';
    const verdict = lvl === 'safe'
        ? `<div class="reader-verdict safe"><i class="fas fa-check-circle" aria-hidden="true"></i><span>Safe · nothing unusual found</span><button type="button" onclick="openEmailModal('${email.id}')">Scan details</button></div>`
        : `<div class="reader-verdict ${lvl}"><i class="fas fa-exclamation-triangle" aria-hidden="true"></i><span>${lvl === 'dangerous' ? 'Dangerous' : 'Worth a look'}${why ? ' · ' + escHtml(why) : ''}</span><button type="button" onclick="openEmailModal('${email.id}')">See why it was flagged →</button></div>`;
    bodyEl.innerHTML = `
        ${verdict}
        <article class="reader" aria-label="Email">
            <header class="reader-head">
                <div class="reader-avatar" aria-hidden="true">${escHtml(initial)}</div>
                <div class="reader-who">
                    <div class="reader-from"><strong>${escHtml(fromName || fromAddr || from)}</strong>${fromAddr && fromName ? ` <span>&lt;${escHtml(fromAddr)}&gt;</span>` : ''}</div>
                    <div class="reader-to">to ${escHtml(email.to || 'me')}</div>
                </div>
                <time class="reader-date">${formatDate(email.date)}</time>
            </header>
            ${atts.length ? `<div class="reader-atts">${atts.map(a => `<span class="reader-att"><i class="fas fa-paperclip" aria-hidden="true"></i>${escHtml(a.filename || 'attachment')}</span>`).join('')}</div>` : ''}
            <div class="reader-body">${text
                ? highlightLinks(text)
                : `<span class="reader-empty">This email has no plain-text version, so only its preview is available:</span>\n\n${escHtml(email.snippet || '')}`}</div>
            <p class="reader-note"><i class="fas fa-shield-alt" aria-hidden="true"></i> Shown as plain text: links can't be clicked and images don't load, so it's safe to read.</p>
        </article>`;

    modal.style.display = 'flex';
    bodyEl.scrollTop = 0;
    attachSenderProfile(email.from);
}

function closeModal() {
    document.getElementById('emailModal').style.display = 'none';
}

// ============================================================
// HONEYPOT
// ============================================================
function initHoneypotToggle() {
    const toggle = document.getElementById('honeypotSwitch');
    const label  = document.getElementById('honeypotLabel');

    toggle?.addEventListener('change', async function () {
        const active = this.checked;
        label.textContent   = active ? 'Active' : 'Inactive';
        label.style.color   = active ? 'var(--success-color)' : 'var(--text-muted)';

        // Sync with settings API
        await apiFetch(`${API_BASE}/api/settings`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ honeypotMode: active })
        });

        showToast(active ? 'Honeypot Activated' : 'Honeypot Deactivated',
            active ? 'Auto-engage mode is now active' : 'Honeypot mode disabled', 'info');
    });

    document.getElementById('refreshSessions')?.addEventListener('click', loadHoneypotSessions);
}

// FIX: safe wrapper — looks up email data from map instead of relying on
// inline HTML attributes that break when from/subject contain quotes or angle brackets
function engageHoneypotById(emailId) {
    const email = emailDataMap[emailId] || cachedEmails.find(e => e.id === emailId);
    if (!email) { showToast('Error', 'Email not found', 'warning'); return; }
    engageHoneypot(email.id, email.from, email.subject);
}

async function engageHoneypot(emailId, senderEmail, subject) {
    // FIX 1: Extract Reply-To from the cached email so we reply to the actual
    // scammer address, not Google's no-reply From address.
    const cachedEmail  = cachedEmails.find(e => e.id === emailId);
    const replyTo      = cachedEmail?.replyTo  || null;
    const threadId     = cachedEmail?.threadId || null;
    const messageId    = cachedEmail?.messageId || null; // Message-ID for In-Reply-To threading
    const actualTarget = replyTo || senderEmail;

    showToast('Engaging Honeypot', `Sending reply to ${actualTarget}...`, 'info');

    try {
        const res  = await apiFetch(`${API_BASE}/api/honeypot/engage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            // pass emailBody so AI can craft a contextual reply to what the scammer wrote
            body: JSON.stringify({ 
                emailId, senderEmail, replyTo, threadId, messageId, subject,
                emailBody: cachedEmail?.body || cachedEmail?.snippet || ''
            })
        });
        const data = await res.json();

        if (data.success) {
            showToast('Honeypot Engaged!',
                `Reply sent to ${actualTarget}. Time-wasting started!`, 'success');
            // ── CHANGE: Fix 1 — navigate to honeypot page so user sees the
            // conversation starting from the original email, not a new tab ──
            setTimeout(() => nav('honeypot'), 800);
            await loadHoneypotSessions();
        } else if (data.alreadyActive) {
            showToast('Already engaged', 'Nami is already talking to this scammer.', 'info');
            setTimeout(() => nav('honeypot'), 800);
        } else if (data.noReplyBlocked) {
            // FIX: specific message when email has no real scammer Reply-To address
            showToast('Not a Scammer Email',
                'This is a real system email with no Reply-To. Honeypot only works on phishing emails.', 'warning');
        } else {
            showToast('Honeypot Error', data.error || 'Could not send reply', 'danger');
        }
    } catch (err) {
        showToast('Honeypot Error', 'Backend not reachable', 'danger');
    }
}

function renderLeaderboard(lb) {
    if (!lb) return;
    document.getElementById('hpMonthMinutes').textContent = `${lb.monthMinutes || 0} min`;
    document.getElementById('hpMostReplies').textContent = lb.mostReplies || 0;
    const list = document.getElementById('hpBoardList');
    const rows = (lb.longest || []).filter(x => x.minutesWasted > 0 || x.repliesSent > 0);
    list.innerHTML = rows.length
        ? rows.map(x => `<li><span class="who">${escHtml(x.senderEmail)}</span><span>${x.repliesSent} ${x.repliesSent === 1 ? 'reply' : 'replies'}</span><b>${x.minutesWasted} min</b></li>`).join('')
        : '<li class="empty">No conversations yet.</li>';
}

let lastIntel = null;
async function loadIntel() {
    const box = document.getElementById('hpIntel'); if (!box) return;
    try {
        const data = await (await apiFetch(`${API_BASE}/api/honeypot/intel`)).json();
        lastIntel = data;
        const t = data.total || {};
        const label = { bankAccounts: 'Bank accounts', ibans: 'IBANs', swift: 'SWIFT codes', crypto: 'Crypto wallets', phones: 'Phone numbers', telegram: 'Telegram', emails: 'Email addresses', urls: 'Links' };
        const rows = Object.keys(label).filter(k => (t[k] || []).length);
        box.innerHTML = rows.length
            ? rows.map(k => `<div class="mi-row"><span>${label[k]}</span><div>${t[k].map(v => `<code>${escHtml(v)}</code>`).join('')}</div></div>`).join('')
            : '<p class="hp-sub">Nothing collected yet. When a scammer replies with payment details or contact numbers, they appear here.</p>';
    } catch (_) {}
}
function exportIntel() {
    if (!lastIntel || !(lastIntel.sessions || []).length) { showToast('Nothing to export', 'No scammer details collected yet', 'info'); return; }
    const blob = new Blob([JSON.stringify({ generated: new Date().toISOString(), tool: 'Genjutsu · Nami', ...lastIntel }, null, 2)], { type: 'application/json' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `genjutsu-scammer-intel-${new Date().toISOString().slice(0, 10)}.json`; a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
async function savePersona(value) {
    await apiFetch(`${API_BASE}/api/settings`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ honeypotPersona: value }) });
    showToast('Persona saved', `Nami will play: ${document.querySelector('#hpPersona option:checked').textContent}`, 'success');
}

async function loadHoneypotSessions() {
    const list = document.getElementById('honeypotSessionsList');

    try {
        const res  = await apiFetch(`${API_BASE}/api/honeypot/sessions`);
        const data = await res.json();

        document.getElementById('hpActiveSessions').textContent = data.activeConversations || 0;
        renderLeaderboard(data.leaderboard);
        loadIntel();
        document.getElementById('hpTimeWasted').textContent = `${data.totalMinutesWasted || 0} min`;
        // FIX 2: use victimsProtected from backend (scoped to this user), not a made-up formula
        document.getElementById('hpVictims').textContent = data.victimsProtected || 0;

        if (!data.sessions || data.sessions.length === 0) {
            list.innerHTML = `<div class="empty-state">
                <i class="fas fa-bullseye"></i>
                <p>No conversations yet. Turn on honeypot mode, then engage a dangerous email.</p>
            </div>`;
            return;
        }

        list.innerHTML = data.sessions.map(s => `
            <div class="honeypot-session" id="session-${s.sessionId}">
                <div class="session-header">
                    <div class="session-status ${s.status === 'active' ? 'active' : ''}"></div>
                    <h4>${escHtml(s.subject || 'Scam Email')}</h4>
                    <span class="session-duration">${s.minutesWasted} min wasted</span>
                </div>
                <p class="session-meta">Nami as <b>${escHtml(s.personaLabel || 'Retired teacher, 72')}</b>${s.status !== 'active' ? ` · ended${s.stopReason ? ': ' + escHtml(s.stopReason) : ''}` : ' · active'}</p>
                <dl class="session-details">
                    <div><dt>Scammer</dt><dd>${escHtml(s.senderEmail)}</dd></div>
                    <div><dt>Replies sent</dt><dd>${s.repliesSent}</dd></div>
                    <div><dt>Started</dt><dd>${formatDate(s.startedAt)}</dd></div>
                </dl>
                <div class="session-actions">
                    <button class="btn btn-sm btn-secondary"
                        onclick="toggleHoneypotMessages('${s.sessionId}')">
                        <i class="fas fa-comments"></i> View Conversation
                    </button>
                    ${s.status === 'active' ? `<button class="btn btn-sm btn-danger"
                        onclick="endHoneypotSession('${s.sessionId}')">End Session</button>` : ''}
                </div>
                <div class="honeypot-messages" id="hp-msgs-${s.sessionId}"
                    style="display:none"></div>
            </div>`).join('');

    } catch (err) {
        list.innerHTML = `<div class="empty-state error">
            <i class="fas fa-exclamation-circle"></i><p>Could not load sessions.</p></div>`;
    }
}

// ── CHANGE: Inline conversation viewer — no new tab needed ───
// Toggles the message panel inside each session card.
// Fetches from /api/honeypot/sessions/:id/messages (user-facing endpoint).
async function toggleHoneypotMessages(sessionId) {
    const panel = document.getElementById(`hp-msgs-${sessionId}`);
    if (!panel) return;

    // If already open, just close it
    if (panel.style.display !== 'none') {
        panel.style.display = 'none';
        return;
    }

    panel.style.display = 'flex';
    panel.innerHTML = '<p style="color:var(--text-muted);font-size:12px">Loading conversation...</p>';

    try {
        const res  = await apiFetch(`${API_BASE}/api/honeypot/sessions/${sessionId}/messages`);
        const data = await res.json();

        if (!data.success || !data.messages || data.messages.length === 0) {
            panel.innerHTML = '<p style="color:#64748b;font-size:12px">No messages yet.</p>';
            return;
        }

        panel.innerHTML = data.messages.map(m => {
            const isOut = m.direction === 'outbound';
            return `
            <div class="hp-bubble ${isOut ? 'out' : 'in'}">
                <b>${isOut ? 'Nami (as you)' : 'Scammer'} <span class="hp-time">${new Date(m.sentAt).toLocaleString()}</span></b>
                ${escHtml(m.body || '(No content)')}
            </div>`;
        }).join('');
    } catch (err) {
        panel.innerHTML = '<p style="color:#ef4444;font-size:12px">Could not load messages.</p>';
    }
}

async function endHoneypotSession(sessionId) {
    if (!confirm('End this honeypot session?')) return;

    // FIX 3: use sessionId (not emailId) to match the DELETE route in honeypot.js
    const res  = await apiFetch(`${API_BASE}/api/honeypot/sessions/${sessionId}`, { method: 'DELETE' });
    const data = await res.json();

    if (data.success) {
        showToast('Session Ended', 'Honeypot session closed successfully', 'success');
        await loadHoneypotSessions();
    }
}

async function blockThreat(emailId) {
    if (!confirm('Block this sender? The email will be moved to your spam/junk folder and future emails from this sender will be filtered automatically.')) return;
    const email = cachedEmails.find(e => e.id === emailId) || emailDataMap[emailId];
    try {
        const res = await apiFetch(`${API_BASE}/api/emails/${encodeURIComponent(emailId)}/block`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                senderEmail: email?.from    || '',
                subject:     email?.subject || ''
            })
        });
        const data = await res.json();
        if (!data.success) throw new Error(data.error);
        // Remove from threats page visually
        const card = document.getElementById(`threat-${emailId}`);
        if (card) { card.style.opacity = '0.4'; setTimeout(() => card.remove(), 600); }
        showToast('Blocked', 'Email moved to spam/junk. Sender filtered.', 'success');
    } catch (err) {
        showToast('Error', 'Could not block: ' + err.message, 'warning');
    }
}

async function unblockEmail(gmailMsgId) {
    try {
        const res  = await apiFetch(`${API_BASE}/api/emails/${encodeURIComponent(gmailMsgId)}/block`, { method: 'DELETE' });
        const data = await res.json();
        if (!data.success) throw new Error(data.error);
        showToast('Unblocked', 'Email restored to your inbox', 'success');
        loadEmails('blocked');
    } catch (err) {
        showToast('Error', 'Could not unblock: ' + err.message, 'warning');
    }
}

// ============================================================
// SETTINGS
// ============================================================
function initSettings() {
    // Load saved settings from backend
    apiFetch(`${API_BASE}/api/settings`).then(r => r.json()).then(data => {
        if (!data.success) return;
        const settings = data.settings;

        document.querySelectorAll('[data-setting]').forEach(input => {
            const key = input.dataset.setting;
            if (key in settings) input.checked = settings[key];
        });
        // Keep sound flag in sync with the toggle
        if ('soundAlerts' in settings) soundAlertsEnabled = !!settings.soundAlerts;
        const personaSel = document.getElementById('hpPersona');
        if (personaSel && settings.honeypotPersona) personaSel.value = settings.honeypotPersona;

        // Sync honeypot toggle
        const hpSwitch = document.getElementById('honeypotSwitch');
        if (hpSwitch && settings.honeypotMode !== undefined) {
            hpSwitch.checked = settings.honeypotMode;
            const label = document.getElementById('honeypotLabel');
            if (label) {
                label.textContent = settings.honeypotMode ? 'Active' : 'Inactive';
                label.style.color = settings.honeypotMode
                    ? 'var(--success-color)' : 'var(--text-muted)';
            }
        }
    }).catch(() => {});

    // Save on toggle
    document.querySelectorAll('[data-setting]').forEach(input => {
        input.addEventListener('change', async function () {
                if (this.dataset.setting === 'soundAlerts') soundAlertsEnabled = this.checked;
            const key   = this.dataset.setting;
            const value = this.checked;

            await apiFetch(`${API_BASE}/api/settings`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ [key]: value })
            });

            const name   = this.closest('.setting-item').querySelector('h4').textContent;
            const status = value ? 'enabled' : 'disabled';
            showToast('Setting Updated', `${name} has been ${status}`, 'success');

            // Keep honeypot page toggle in sync
            if (key === 'honeypotMode') {
                const hpSwitch = document.getElementById('honeypotSwitch');
                if (hpSwitch) hpSwitch.checked = value;
                const label = document.getElementById('honeypotLabel');
                if (label) {
                    label.textContent = value ? 'Active' : 'Inactive';
                    label.style.color = value ? 'var(--success-color)' : 'var(--text-muted)';
                }
            }
        });
    });

    document.getElementById('reconnectGmail')?.addEventListener('click', async function () {
        const provider = window.genjutsuProvider || 'google';
        if (provider === 'microsoft') { window.location.href = `${API_BASE}/auth/microsoft`; return; }
        if (provider === 'google')    { window.location.href = `${API_BASE}/auth/google`;    return; }
        // IMAP mailboxes reconnect by signing in again with an app password
        await apiFetch(`${API_BASE}/auth/logout`);
        window.location.reload();
    });
}

// ============================================================
// EMAIL FILTERS
// ============================================================
function initFilters() {
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', function () {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            this.classList.add('active');
            currentFilter = this.dataset.filter; // track active filter
            loadEmails(currentFilter);
        });
    });
}

// ============================================================
// SEARCH
// Typing filters the emails already on screen. Pressing Enter searches the
// whole mailbox (older emails too) and checks every result the same way.
// ============================================================

function initSearchFilter() {
    const searchInput = document.getElementById('searchInput');
    if (!searchInput || searchInput.dataset.bound) return;
    searchInput.dataset.bound = '1';
    searchInput.setAttribute('placeholder', 'Search emails… (Enter searches all mail)');
    searchInput.setAttribute('enterkeyhint', 'search');

    searchInput.addEventListener('input', function () {
        const term = this.value.toLowerCase();
        document.querySelectorAll('#emailList .email-item').forEach(item => {
            item.style.display = item.textContent.toLowerCase().includes(term) ? '' : 'none';
        });
        if (!term && mailboxSearch) exitMailboxSearch();
    });
    searchInput.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { e.preventDefault(); searchMailbox(this.value); }
        if (e.key === 'Escape' && mailboxSearch) { this.value = ''; exitMailboxSearch(); }
    });
}

function searchBanner(html) {
    let el = document.getElementById('mailboxSearchBanner');
    if (!html) { el?.remove(); return; }
    if (!el) {
        el = document.createElement('div');
        el.id = 'mailboxSearchBanner';
        el.className = 'mailbox-search-banner';
        el.setAttribute('role', 'status');
        const list = document.getElementById('emailList');
        list.parentNode.insertBefore(el, list);
    }
    el.innerHTML = html;
}

async function searchMailbox(raw) {
    const q = String(raw || '').trim();
    if (q.length < 2) { showToast('Search', 'Type at least 2 characters, then press Enter.', 'info'); return; }
    if (document.querySelector('.nav-item.active')?.dataset?.page !== 'emails') {
        document.querySelector('.nav-item[data-page="emails"]')?.click();
    }
    mailboxSearch = q;
    const list = document.getElementById('emailList');
    const countEl = document.getElementById('emailCountInfo');
    searchBanner(`<i class="fas fa-search" aria-hidden="true"></i><span>Searching your whole mailbox for <strong>${escHtml(q)}</strong>…</span>`);
    list.innerHTML = `<div class="loading-state"><i class="fas fa-spinner fa-spin"></i><p>Searching older emails and checking each one…</p></div>`;
    try {
        const res  = await apiFetch(`${API_BASE}/api/emails/search?q=${encodeURIComponent(q)}&limit=50`);
        const data = await res.json();
        if (mailboxSearch !== q) return;   // a newer search or "Back to latest" happened meanwhile
        if (!data.success) throw new Error(data.error || 'Search failed');
        data.emails.forEach(e => { emailDataMap[e.id] = e; });
        const n = data.emails.length;
        const risky = data.emails.filter(e => ((e.threat || {}).overrideLevel || (e.threat || {}).level) !== 'safe').length;
        searchBanner(`<i class="fas fa-search" aria-hidden="true"></i>
            <span>${n ? `${n} result${n === 1 ? '' : 's'}` : 'No results'} from your whole mailbox for <strong>${escHtml(q)}</strong>${n ? ` · ${risky ? `${risky} need${risky === 1 ? 's' : ''} a look` : 'all look safe'}` : ''}${n >= 50 ? ' · showing the newest 50' : ''}</span>
            <button type="button" class="btn-link" onclick="exitMailboxSearch(true)">Back to latest emails</button>`);
        countEl.textContent = `${n} search result${n === 1 ? '' : 's'}`;
        if (!n) {
            list.innerHTML = `<div class="empty-state"><i class="fas fa-search"></i><p>Nothing in your mailbox matches “${escHtml(q)}”. Try a sender's address, a word from the subject, or a shorter word.</p></div>`;
            return;
        }
        renderEmailList(data.emails);
    } catch (err) {
        if (mailboxSearch !== q) return;
        searchBanner(`<i class="fas fa-exclamation-circle" aria-hidden="true"></i><span>${escHtml(err.message || 'Search failed')}</span>
            <button type="button" class="btn-link" onclick="exitMailboxSearch(true)">Back to latest emails</button>`);
        list.innerHTML = `<div class="empty-state error"><i class="fas fa-exclamation-circle"></i><p>Could not search your mailbox. <a href="#" onclick="searchMailbox(mailboxSearch || '');return false;">Try again</a></p></div>`;
    }
}

function exitMailboxSearch(clearBox = false) {
    mailboxSearch = null;
    searchBanner(null);
    if (clearBox) { const i = document.getElementById('searchInput'); if (i) i.value = ''; }
    loadEmails(currentFilter);
}

// ============================================================
// SELECT ALL EMAILS
// ============================================================
function initSelectAll() {
    const monitoringControls = document.querySelector('.monitoring-controls');
    if (!monitoringControls || document.getElementById('selectAll')) return;

    const wrap = document.createElement('div');
    wrap.innerHTML = `<label style="display:flex;align-items:center;gap:8px;
        color:var(--text-secondary);cursor:pointer;">
        <input type="checkbox" id="selectAll" style="width:18px;height:18px;">
        <span style="font-size:14px;">Select All</span></label>`;
    monitoringControls.insertBefore(wrap, monitoringControls.firstChild);

    const selectAll = document.getElementById('selectAll');
    selectAll.addEventListener('change', function () {
        document.querySelectorAll('.email-checkbox').forEach(cb => cb.checked = this.checked);
    });
}

// ============================================================
// MISC BUTTONS
// ============================================================
function initButtons() {
    // Scan Now
    document.getElementById('scanNow')?.addEventListener('click', async function () {
        const icon = this.querySelector('i');
        icon.style.animation = 'spin 1s linear infinite';
        this.disabled = true;

        // Stay in whichever filter is currently active — don't reset to 'all'
        await loadEmails(currentFilter);
        await loadDashboard();
        await loadThreats();

        icon.style.animation = '';
        this.disabled = false;
        showToast('Scan Complete',
            `Inbox rescanned. Showing ${currentFilter === 'all' ? 'all' : currentFilter} emails.`, 'success');
    });

    // Export report — calls backend, downloads real PDF for this user's Gmail
    document.getElementById('exportReport')?.addEventListener('click', async function () {
        const btn  = this;
        const icon = btn.querySelector('i');

        btn.disabled         = true;
        btn.textContent      = '';
        const spinner        = document.createElement('i');
        spinner.className    = 'fas fa-spinner fa-spin';
        btn.appendChild(spinner);
        btn.appendChild(document.createTextNode(' Generating...'));

        showToast('Generating Report', 'Building your personalised PDF report...', 'info');

        try {
            const response = await apiFetch(`${API_BASE}/api/threats/report`);

            if (!response.ok) {
                const err = await response.json().catch(() => ({}));
                throw new Error(err.error || 'Server error');
            }

            // Get filename from Content-Disposition header if available
            const cd       = response.headers.get('Content-Disposition') || '';
            const match    = cd.match(/filename="?([^"]+)"?/);
            const filename = match ? match[1] : `genjutsu-report-${Date.now()}.pdf`;

            // Stream the PDF blob and trigger browser download
            const blob = await response.blob();
            const url  = URL.createObjectURL(blob);
            const a    = document.createElement('a');
            a.href     = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            showToast('Report Downloaded', `${filename} saved to your downloads folder.`, 'success');

        } catch (err) {
            console.error('Report error:', err);
            showToast('Report Failed', err.message || 'Could not generate report. Try scanning emails first.', 'danger');
        } finally {
            btn.disabled    = false;
            btn.innerHTML   = '<i class="fas fa-download"></i> Export Report';
        }
    });

    // Time filter
    document.getElementById('timeFilter')?.addEventListener('change', function () {
        showToast('Updating Chart', `Loading data for: ${this.value}`, 'info');
        loadDashboard();
    });

    // Spin animation
    const style = document.createElement('style');
    style.textContent = `@keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }`;
    document.head.appendChild(style);
}

// ============================================================
// HELPERS
// ============================================================
function animateNumber(el, target, duration = 1000) {
    if (!el) return;
    const increment = target / (duration / 16);
    let current = 0;
    const timer = setInterval(() => {
        current += increment;
        if (current >= target) {
            el.textContent = target.toLocaleString();
            clearInterval(timer);
        } else {
            el.textContent = Math.floor(current).toLocaleString();
        }
    }, 16);
}

function escHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// =============================================================
// NOTIFICATION PANEL — Two sections: Threat alerts + Admin remarks
// =============================================================

async function loadNotifications() {
    try {
        // Fetch both in parallel
        const [alertRes, remarkRes] = await Promise.all([
            apiFetch(`${API_BASE}/api/notifications`),
            apiFetch(`${API_BASE}/api/notifications/remarks`)
        ]);
        const alertData  = await alertRes.json();
        const remarkData = await remarkRes.json();

        // ── Update threat badge (red) ─────────────────────────
        const badge = document.getElementById('notifBadge');
        const alertCount = alertData.success ? (alertData.count || 0) : 0;
        if (badge) {
            badge.textContent    = alertCount;
            badge.style.display  = alertCount > 0 ? 'flex' : 'none';
        }

        // ── Update remark badge (purple) ──────────────────────
        const remarkBadge = document.getElementById('notifRemarkBadge');
        const remarkCount = remarkData.success ? (remarkData.count || 0) : 0;
        if (remarkBadge) {
            remarkBadge.textContent   = remarkCount;
            remarkBadge.style.display = remarkCount > 0 ? 'flex' : 'none';
        }

        renderNotifications(alertData.alerts || [], remarkData.remarks || []);
    } catch (err) {
        console.warn('Notification load error:', err.message);
    }
}

function renderNotifications(alerts, remarks) {
    const list = document.getElementById('notifList');
    if (!list) return;

    let html = '';

    // ── Section 1: Admin Remarks ──────────────────────────────
    html += `<div class="notif-section-header remark-header">
        <i class="fas fa-comment-dots"></i> Admin Remarks
        ${remarks.length > 0 ? `<button class="notif-clear-inline" onclick="markRemarksRead()">Clear</button>` : ''}
    </div>`;

    if (remarks.length === 0) {
        html += `<div class="notif-empty-small">
            <i class="fas fa-comment-slash"></i> No new remarks from admin.
        </div>`;
    } else {
        html += remarks.map(r => {
            const subject = r.subject || 'Email';
            const time    = r.created_at
                ? new Date(r.created_at).toLocaleString('en-GB',{dateStyle:'short',timeStyle:'short'})
                : '';
            const levelMap = { dangerous: 'danger', suspicious: 'suspicious', safe: 'safe' };
            const levelCls = levelMap[r.new_level] || 'suspicious';
            const levelLabel = r.new_level
                ? `<span class="notif-level-tag ${levelCls}">${r.new_level}</span>` : '';
            const emailId = r.email_id || '';
            const senderEmail = r.sender_email || '';
            // Toggle button to view the email content
            const viewToggle = emailId ? `
                <button class="notif-view-btn" onclick="toggleRemarkEmail('${emailId}', this)"
                    style="margin-top:6px;font-size:11px;background:rgba(99,102,241,.1);color:#818cf8;
                    border:1px solid rgba(99,102,241,.2);border-radius:6px;padding:3px 10px;cursor:pointer">
                    <i class="fas fa-envelope" style="font-size:10px"></i> View Email ▾
                </button>
                <div id="remark-email-${emailId}" style="display:none;margin-top:8px;
                    background:var(--bg-primary);border:1px solid var(--border-color);border-radius:8px;padding:10px;font-size:12px">
                    <div style="color:var(--text-muted);margin-bottom:4px"><strong>Subject:</strong> ${escHtml(subject)}</div>
                    ${senderEmail ? `<div style="color:var(--text-muted);margin-bottom:4px"><strong>From:</strong> ${escHtml(senderEmail)}</div>` : ''}
                    <div style="color:#64748b;font-size:11px;margin-top:6px">
                        <button onclick="openEmailFromRemark('${emailId}')"
                            style="background:rgba(99,102,241,.15);color:#818cf8;border:1px solid rgba(99,102,241,.25);
                            border-radius:6px;padding:4px 12px;cursor:pointer;font-size:11px">
                            <i class="fas fa-eye"></i> Open Full Email
                        </button>
                    </div>
                </div>` : '';
            return `<div class="notif-item unread remark-item">
                <div class="notif-icon remark">
                    <i class="fas fa-user-shield"></i>
                </div>
                <div class="notif-content">
                    <div class="notif-title">${escHtml(subject)} ${levelLabel}</div>
                    <div class="notif-remark-text">"${escHtml(r.note || '')}"</div>
                    <div class="notif-meta">By ${escHtml(r.overridden_by || 'Admin')} &bull; ${time}</div>
                    ${viewToggle}
                </div>
            </div>`;
        }).join('');
    }

    // ── Section 2: Threat Email Alerts ───────────────────────
    html += `<div class="notif-section-header alert-header">
        <i class="fas fa-exclamation-triangle"></i> Threat Alerts
        ${alerts.length > 0 ? `<button class="notif-clear-inline" onclick="markAllRead()">Clear</button>` : ''}
    </div>`;

    if (alerts.length === 0) {
        html += `<div class="notif-empty-small">
            <i class="fas fa-check-circle"></i> No unread threat alerts.
        </div>`;
    } else {
        html += alerts.map(a => {
            const level   = a.alert_type || 'suspicious';
            const icon    = level === 'dangerous' ? 'fa-exclamation-circle' : 'fa-exclamation-triangle';
            const subject = a.subject || a.message || 'Threat detected';
            const sender  = a.sender_email || '';
            const time    = a.created_at
                ? new Date(a.created_at).toLocaleString('en-GB',{dateStyle:'short',timeStyle:'short'})
                : '';
            return `<div class="notif-item unread ${level}">
                <div class="notif-icon ${level}">
                    <i class="fas ${icon}"></i>
                </div>
                <div class="notif-content">
                    <div class="notif-title">${escHtml(subject)}</div>
                    ${sender ? `<div class="notif-msg">From: ${escHtml(sender)}</div>` : ''}
                    <div class="notif-time">${time}</div>
                </div>
            </div>`;
        }).join('');
    }

    list.innerHTML = html;
}

function toggleRemarkEmail(emailId, btn) {
    const panel = document.getElementById(`remark-email-${emailId}`);
    if (!panel) return;
    const isOpen = panel.style.display !== 'none';
    panel.style.display = isOpen ? 'none' : 'block';
    btn.innerHTML = isOpen
        ? '<i class="fas fa-envelope" style="font-size:10px"></i> View Email ▾'
        : '<i class="fas fa-envelope-open" style="font-size:10px"></i> Hide Email ▴';
}

function openEmailFromRemark(emailId) {
    closeNotifPanel();
    // Try to open modal directly if email is cached
    const email = emailDataMap[emailId] || cachedEmails.find(e => e.id === emailId);
    if (email) {
        openEmailModal(emailId);
    } else {
        // Navigate to threats page where it will be loaded
        document.querySelector('.nav-item[data-page="threats"]')?.click();
        showToast('Info', 'Find the email in the Threats Detected page', 'info');
    }
}

function openNotifPanel() {
    const panel = document.getElementById('notifPanel');
    if (panel?.classList.contains('open')) {
        closeNotifPanel();
    } else {
        panel?.classList.add('open');
        document.getElementById('notifOverlay')?.classList.add('open');
    }
}

function closeNotifPanel() {
    document.getElementById('notifPanel')?.classList.remove('open');
    document.getElementById('notifOverlay')?.classList.remove('open');
}

async function markAllRead() {
    try {
        await apiFetch(`${API_BASE}/api/notifications/read`, { method: 'PUT' });
        const badge = document.getElementById('notifBadge');
        if (badge) { badge.textContent = '0'; badge.style.display = 'none'; }
        // Re-render with cleared alerts
        const remarkRes  = await apiFetch(`${API_BASE}/api/notifications/remarks`);
        const remarkData = await remarkRes.json();
        renderNotifications([], remarkData.remarks || []);
        showToast('Done', 'Threat alerts cleared', 'success');
    } catch (err) {
        showToast('Error', 'Could not clear alerts', 'danger');
    }
}

async function markRemarksRead() {
    try {
        await apiFetch(`${API_BASE}/api/notifications/remarks/read`, { method: 'PUT' });
        const badge = document.getElementById('notifRemarkBadge');
        if (badge) { badge.textContent = '0'; badge.style.display = 'none'; }
        // Re-render with cleared remarks
        const alertRes  = await apiFetch(`${API_BASE}/api/notifications`);
        const alertData = await alertRes.json();
        renderNotifications(alertData.alerts || [], []);
        showToast('Done', 'Admin remarks cleared', 'success');
    } catch (err) {
        showToast('Error', 'Could not clear remarks', 'danger');
    }
}

// Override the notification button to open panel instead of switching page
document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('notificationBtn');
    if (btn) {
        const newBtn = btn.cloneNode(true);
        btn.parentNode.replaceChild(newBtn, btn);
        newBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            openNotifPanel();
        });
    }
});

// =============================================================
// AI CHAT BOT
// =============================================================

let aiChatOpen = false;
let aiLoading  = false;

function toggleAIChat() {
    aiChatOpen = !aiChatOpen;
    const panel  = document.getElementById('aiChatPanel');
    const bubble = document.getElementById('aiChatBubble');
    panel?.classList.toggle('open', aiChatOpen);
    if (bubble) bubble.style.background = aiChatOpen
        ? 'linear-gradient(135deg,#7c3aed,#6366f1)'
        : 'linear-gradient(135deg,#6366f1,#7c3aed)';
}

function sendAISuggestion(btn) {
    const text = btn.textContent;
    // Remove suggestions after first use
    btn.closest('.ai-suggestions')?.remove();
    sendAIMessage(text);
}

async function sendAIMessage(overrideText) {
    if (aiLoading) return;

    const input   = document.getElementById('aiInput');
    const message = overrideText || input?.value?.trim();
    if (!message) return;

    if (input) input.value = '';

    // Add user message
    addAIMessage(message, 'user');

    // Show typing indicator
    const typingId = addTypingIndicator();
    aiLoading = true;

    const sendBtn = document.querySelector('.ai-send-btn');
    if (sendBtn) sendBtn.disabled = true;

    try {
        // Build context from cached data
        const ctx = `User has ${cachedEmails.length} emails loaded. ` +
            `Dangerous: ${cachedEmails.filter(e => e.threat?.level === 'dangerous').length}. ` +
            `Suspicious: ${cachedEmails.filter(e => e.threat?.level === 'suspicious').length}. ` +
            `Safe: ${cachedEmails.filter(e => e.threat?.level === 'safe').length}.`;

        const res  = await apiFetch(`${API_BASE}/api/ai/chat`, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ message, context: ctx })
        });
        const data = await res.json();

        removeTypingIndicator(typingId);
        addAIMessage(data.reply || 'Sorry, I could not get a response. Please try again.', 'ai');

    } catch (err) {
        removeTypingIndicator(typingId);
        addAIMessage('Sorry, I am having trouble connecting. Make sure the backend is running.', 'ai');
    } finally {
        aiLoading = false;
        if (sendBtn) sendBtn.disabled = false;
        if (input) input.focus();
    }
}

function addAIMessage(text, role) {
    const container = document.getElementById('aiMessages');
    if (!container) return;

    const div = document.createElement('div');
    div.className = `ai-msg ${role}`;
    div.innerHTML = `<div class="ai-msg-bubble">${escHtml(text)}</div>`;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

function addTypingIndicator() {
    const container = document.getElementById('aiMessages');
    if (!container) return null;
    const id  = 'typing-' + Date.now();
    const div = document.createElement('div');
    div.className = 'ai-msg ai ai-typing';
    div.id = id;
    div.innerHTML = `<div class="ai-msg-bubble">
        <div class="dot"></div><div class="dot"></div><div class="dot"></div>
    </div>`;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
    return id;
}

function removeTypingIndicator(id) {
    if (id) document.getElementById(id)?.remove();
}

// =============================================================
// AI EMAIL SUMMARISE — called from email modal
// =============================================================

async function summariseEmailWithAI(emailId) {
    const email = cachedEmails.find(e => e.id === emailId);
    if (!email) return;

    const box = document.getElementById('aiSummaryBox');
    if (!box) return;

    box.innerHTML = `<div class="ai-summary-label">
        <i class="fas fa-robot"></i> Genjutsu AI
    </div>
    <div><i class="fas fa-spinner fa-spin" style="margin-right:6px"></i> Analysing email...</div>`;

    try {
        const res  = await apiFetch(`${API_BASE}/api/ai/summarise`, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({
                subject: email.subject,
                from:    email.from,
                body:    email.body,
                threat:  email.threat
            })
        });
        const data = await res.json();

        box.innerHTML = `<div class="ai-summary-label">
            <i class="fas fa-robot"></i> AI Summary
        </div>
        <div>${escHtml(data.summary || 'Could not generate summary.')}</div>`;

    } catch (err) {
        box.innerHTML = `<div class="ai-summary-label">
            <i class="fas fa-robot"></i> AI Summary
        </div>
        <div style="color:var(--text-muted)">AI summary unavailable. Check your ANTHROPIC_API_KEY.</div>`;
    }
}

// =============================================================
// ALSO CALL loadNotifications on startup
// =============================================================
// Load notifications shortly after the app opens
setTimeout(() => {
    if (document.getElementById('mainApp')?.style.display !== 'none') {
        loadNotifications();
    }
}, 2000);

// =============================================================
// HONEYPOT AUTO-POLL — checks for scammer replies every 2 min
// =============================================================
let honeypotPollInterval = null;

async function pollHoneypot() {
    try {
        const res  = await apiFetch(`${API_BASE}/api/honeypot/poll`, { method: 'POST' });
        const data = await res.json();
        if (data.replied > 0) {
            showToast('Honeypot Active!',
                `Sent ${data.replied} auto-repl${data.replied > 1 ? 'ies' : 'y'} to scammer(s)`, 'success');
            await loadHoneypotSessions(); // refresh session list
        }
    } catch (err) {
        // silent fail — polling should never interrupt the user
    }
}

function startHoneypotPolling() {
    if (honeypotPollInterval) return; // already running
    // Poll every 30 seconds for scammer replies
    honeypotPollInterval = setInterval(pollHoneypot, 30 * 1000);
    console.log('[Honeypot] Auto-poll started (every 30 sec)');
}

// Start polling automatically when app loads
setTimeout(startHoneypotPolling, 5000);

// ============================================================
// AUTO-REFRESH — reload emails & threats every 60 seconds
// ============================================================
let autoRefreshInterval = null;

function startAutoRefresh() {
    if (autoRefreshInterval) return;
    autoRefreshInterval = setInterval(async () => {
        const activeSection = document.querySelector('.nav-item.active')?.dataset?.page;
        if (!mailboxSearch) await loadEmails(currentFilter);   // don't replace search results
        if (activeSection === 'threats') {
            await loadThreats();
        }
    }, 60 * 1000); // every 60 seconds
    console.log('[Genjutsu] Auto-refresh started (60s interval)');
}

// Start auto-refresh 10 seconds after initial load
setTimeout(startAutoRefresh, 10000);


// ============================================================
// LIGHT / DARK THEME
// ============================================================
function themeColors() {
    const cs = getComputedStyle(document.documentElement);
    const v = name => cs.getPropertyValue(name).trim();
    return { text: v('--text-secondary') || '#cbd5e1', muted: v('--text-muted') || '#94a3b8', grid: v('--border-color') || '#334155' };
}

function refreshChartTheme() {
    const c = themeColors();
    if (threatLineChart) {
        const o = threatLineChart.options;
        o.plugins.legend.labels.color = c.text;
        ['x', 'y'].forEach(axis => { o.scales[axis].grid.color = c.grid; o.scales[axis].ticks.color = c.muted; });
        threatLineChart.update('none');
    }
    if (threatPieChart) {
        threatPieChart.options.plugins.legend.labels.color = c.text;
        threatPieChart.update('none');
    }
    [checksChart, domainsChart].forEach(ch => {
        if (!ch) return;
        ch.options.scales.x.ticks.color = c.muted; ch.options.scales.x.grid.color = c.grid; ch.options.scales.y.ticks.color = c.text;
        ch.update('none');
    });
}

function applyTheme(theme) {
    const t = theme === 'light' ? 'light' : 'dark';
    document.documentElement.dataset.theme = t;
    try { localStorage.setItem('gj-theme', t); } catch (e) { /* private mode: theme just won't be remembered */ }
    const next = t === 'dark' ? 'light' : 'dark';
    document.querySelectorAll('.theme-btn').forEach(btn => {
        const icon = btn.querySelector('i');
        if (icon) icon.className = t === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        btn.setAttribute('aria-label', `Switch to ${next} mode`);
        btn.title = `Switch to ${next} mode`;
    });
    const sw = document.getElementById('themeSwitch');
    if (sw) sw.checked = t === 'dark';
    refreshChartTheme();
}

document.addEventListener('DOMContentLoaded', () => {
    applyTheme(document.documentElement.dataset.theme);
    document.querySelectorAll('.theme-btn').forEach(btn => btn.addEventListener('click', () => {
        applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
    }));
    document.getElementById('themeSwitch')?.addEventListener('change', e => applyTheme(e.target.checked ? 'dark' : 'light'));
});


// ============================================================
// DEMO, FIRST-RUN TOUR, SIEM EXPORT, API KEYS
// ============================================================
function alertLoginError(msg) {
    const el = document.getElementById('imapError');
    if (el) { el.textContent = msg; el.style.display = 'block'; } else alert(msg);
}

const TOUR = [
    { icon: 'fa-circle', title: 'The menu lives in the bubble', text: 'Tap the round button at the top left to move between Overview, Inbox, Threats, Honeypot and Settings.' },
    { icon: 'fa-inbox', title: 'Every email gets a badge', text: 'Inbox shows each email with Safe, Suspicious or Dangerous. Open one to read it, then "See why it was flagged" for the evidence.' },
    { icon: 'fa-crosshairs', title: 'Investigate threats', text: 'Threats lists only the risky emails, with every check that fired, MITRE techniques and indicators you can copy or export.' },
    { icon: 'fa-sliders-h', title: 'Make it yours', text: 'In Settings you can quarantine dangerous emails automatically, add trusted senders and rules, and get alerts in Discord.' },
];
let tourIdx = 0;
function startTour(force) {
    let done = false;
    try { done = localStorage.getItem('gj-tour-done') === '1'; } catch (_) {}
    if (done && !force) return;
    const el = document.getElementById('tour');
    if (!el) return;
    tourIdx = 0; renderTour(); el.hidden = false;
    document.getElementById('tourNext').focus();
}
function renderTour() {
    const t = TOUR[tourIdx];
    document.getElementById('tourStep').innerHTML = `<i class="fas ${t.icon}" aria-hidden="true"></i>`;
    document.getElementById('tourTitle').textContent = t.title;
    document.getElementById('tourText').textContent = t.text;
    document.getElementById('tourDots').innerHTML = TOUR.map((_, i) => `<span class="${i === tourIdx ? 'on' : ''}"></span>`).join('');
    document.getElementById('tourNext').textContent = tourIdx === TOUR.length - 1 ? 'Done' : 'Next';
}
function endTour() {
    document.getElementById('tour').hidden = true;
    try { localStorage.setItem('gj-tour-done', '1'); } catch (_) {}
}
document.addEventListener('DOMContentLoaded', () => {
    const next = document.getElementById('tourNext'), skip = document.getElementById('tourSkip');
    if (next) next.addEventListener('click', () => { if (tourIdx < TOUR.length - 1) { tourIdx++; renderTour(); } else endTour(); });
    if (skip) skip.addEventListener('click', endTour);
    document.addEventListener('keydown', (e) => { const t = document.getElementById('tour'); if (e.key === 'Escape' && t && !t.hidden) endTour(); });
});

async function siemExport(format) {
    try {
        const r = await apiFetch(`${API_BASE}/api/account/export/siem?format=${format}&days=30`);
        if (!r.ok) throw new Error('Export failed');
        const blob = await r.blob();
        const ext = { jsonl: 'jsonl', cef: 'cef.log', syslog: 'syslog.log' }[format] || 'txt';
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `genjutsu-events-${new Date().toISOString().slice(0, 10)}.${ext}`;
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    } catch (e) { showToast('Export failed', e.message, 'warning'); }
    return false;
}

async function loadApiKeys() {
    const list = document.getElementById('apiKeyList');
    if (!list) return;
    try {
        const j = await (await apiFetch(`${API_BASE}/api/account/api-keys`)).json();
        const keys = j.keys || [];
        list.innerHTML = keys.length ? keys.map(k => `<li>
            <time>${formatDate(k.created_at)}</time>
            <span class="api-key-row"><strong>${escHtml(k.name || 'Unnamed key')}</strong> <code>${escHtml(k.prefix)}…</code>
            <small>${k.last_used ? 'last used ' + formatDate(k.last_used) : 'never used'}</small>
            <button class="btn btn-secondary btn-sm" type="button" onclick="revokeApiKey('${escHtml(k.key_id)}')">Revoke</button></span></li>`).join('')
            : `<li class="empty">${window.genjutsuDemo ? 'API keys are not available in the demo.' : 'No keys yet.'}</li>`;
    } catch (_) { list.innerHTML = '<li class="empty">Could not load keys.</li>'; }
}
async function createApiKey(e) {
    e.preventDefault();
    const name = document.getElementById('apiKeyName').value.trim();
    const box = document.getElementById('apiKeyNew');
    try {
        const r = await apiFetch(`${API_BASE}/api/account/api-keys`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name }) });
        const j = await r.json();
        if (!j.success) throw new Error(j.error || 'Could not create the key');
        box.innerHTML = `<p><strong>Copy this key now.</strong> It won't be shown again.</p>
            <div class="api-key-show"><code id="apiKeyValue">${escHtml(j.key)}</code>
            <button class="btn btn-secondary btn-sm" type="button" onclick="navigator.clipboard.writeText(document.getElementById('apiKeyValue').textContent).then(()=>showToast('Copied','API key copied','success'))"><i class="fas fa-copy"></i> Copy</button></div>`;
        box.hidden = false;
        document.getElementById('apiKeyName').value = '';
        loadApiKeys();
    } catch (err) { showToast('API key', err.message, 'warning'); }
}
async function revokeApiKey(id) {
    if (!confirm('Revoke this key? Anything using it will stop working.')) return;
    await apiFetch(`${API_BASE}/api/account/api-keys/${encodeURIComponent(id)}`, { method: 'DELETE' });
    document.getElementById('apiKeyNew').hidden = true;
    loadApiKeys();
}


// ── Notices from the Genjutsu team ───────────────────────────
async function loadAnnouncements() {
    const bar = document.getElementById('announceBar');
    if (!bar) return;
    let hidden = [];
    try { hidden = JSON.parse(localStorage.getItem('gj-ann-hidden') || '[]'); } catch (_) {}
    try {
        const j = await (await apiFetch(`${API_BASE}/api/announcements`)).json();
        const list = (j.announcements || []).filter(a => !hidden.includes(a.announcement_id));
        bar.innerHTML = list.map(a => `<div class="announce ${a.level === 'critical' ? 'critical' : a.level === 'warning' ? 'warning' : ''}" role="status">
            <i class="fas ${a.level === 'info' ? 'fa-info-circle' : 'fa-exclamation-triangle'}" aria-hidden="true"></i>
            <span><strong>Genjutsu team:</strong> ${escHtml(a.message)}</span>
            <button type="button" class="announce-x" aria-label="Hide this notice" onclick="hideAnnouncement('${escHtml(a.announcement_id)}')"><i class="fas fa-times"></i></button></div>`).join('');
    } catch (_) { /* notices are optional */ }
}
function hideAnnouncement(id) {
    try { const h = JSON.parse(localStorage.getItem('gj-ann-hidden') || '[]'); h.push(id); localStorage.setItem('gj-ann-hidden', JSON.stringify(h.slice(-30))); } catch (_) {}
    loadAnnouncements();
}


// ── Organization / organization ───────────────────────────────────
// Staff with the organization's email join automatically; others join with an invite link.
async function joinPendingOrg() {
    let code = null;
    try { code = localStorage.getItem('gj-join'); localStorage.removeItem('gj-join'); } catch (_) {}
    if (!code) return;
    if (window.genjutsuDemo) { showToast('Invite link', "The demo account can't join an organization. Sign in with your own email.", 'warning'); return; }
    try {
        const r = await (await apiFetch(`${API_BASE}/api/account/org/join`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code }) })).json();
        if (!r.success) throw new Error(r.error);
        showToast(r.already ? 'Already a member' : 'Joined', r.already ? `You're already part of ${r.name}.` : `You joined ${r.name}. Its admins can now see threats sent to you.`, 'success');
    } catch (e) { showToast("Couldn't join", e.message, 'warning'); }
}
async function loadOrg() {
    const sec = document.getElementById('orgSection'), box = document.getElementById('orgBox');
    if (!sec || !box) return;
    try {
        const { org } = await (await apiFetch(`${API_BASE}/api/account/org`)).json();
        sec.hidden = !org;
        if (!org) return;
        const how = { domain: 'because you use the organization email', invite: 'with an invite link', list: 'because your organization added your email', admin: 'added by an admin' }[org.org_joined] || '';
        box.innerHTML = '';
        const p = document.createElement('p');
        p.className = 'settings-note'; p.style.margin = '0 0 10px';
        p.innerHTML = '<b></b> <span></span>';
        p.querySelector('b').textContent = org.name;
        p.querySelector('span').textContent = `· joined ${how}. Your organization's admins can see your scan results and the threats sent to you. They can't read your other emails.`;
        const btn = document.createElement('button');
        btn.className = 'btn btn-secondary btn-sm'; btn.type = 'button';
        btn.innerHTML = '<i class="fas fa-door-open"></i> Leave';
        btn.onclick = async () => {
            if (!confirm(`Leave ${org.name}? You keep your own protection, and you won't be added back automatically.`)) return;
            await apiFetch(`${API_BASE}/api/account/org/leave`, { method: 'POST' });
            showToast('Left', `You left ${org.name}.`, 'success'); loadOrg();
        };
        box.append(p, btn);
    } catch (_) { sec.hidden = true; }
}
