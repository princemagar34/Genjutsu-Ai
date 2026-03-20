// ============================================================
// script.js — Genjutsu Frontend Logic (fully integrated with backend)
// ============================================================

// ── Backend API base URL ──────────────────────────────────────
const API_BASE = 'https://genjutsu-ai-production.up.railway.app';

// ── Chart instances (so we can update them later) ────────────
let threatLineChart = null;
let threatPieChart  = null;

// ── Current loaded emails cache ──────────────────────────────
let cachedEmails = [];
// FIX: Safe lookup map so onclick handlers never embed raw email data in HTML attributes
// (email.from / email.subject can contain quotes and angle brackets that break onclick)
const emailDataMap = {};

// ============================================================
// INIT — runs on every page load
// ============================================================
document.addEventListener('DOMContentLoaded', async () => {
    await checkAuthAndInit();
});

// ============================================================
// AUTH — check login, then boot app
// ============================================================
async function checkAuthAndInit() {
    try {
        const res  = await fetch(`${API_BASE}/auth/me`, {credentials:'include'});
        const data = await res.json();

        if (!data.loggedIn) {
            showLoginScreen();
            return;
        }

        // Populate user info in sidebar
        document.getElementById('userName').textContent  = data.user.name;
        document.getElementById('userEmail').textContent = data.user.email;
        document.getElementById('gmailConnectedEmail').textContent =
            `Connected: ${data.user.email}`;

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

        // Boot the rest of the UI
        initNavigation();
        initToast();
        initFilters();
        initHoneypotToggle();
        initSettings();
        initEmailModal();
        initButtons();

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

async function logout() {
    await fetch(`${API_BASE}/auth/logout`, {credentials:'include'});
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

    navItems.forEach(item => {
        item.addEventListener('click', function (e) {
            e.preventDefault();
            navItems.forEach(n => n.classList.remove('active'));
            this.classList.add('active');

            const pageName = this.dataset.page;
            pages.forEach(p => p.classList.remove('active'));

            const selectedPage = document.getElementById(`${pageName}-page`);
            if (selectedPage) selectedPage.classList.add('active');

            pageTitle.textContent = this.querySelector('span').textContent;

            if (window.innerWidth <= 768) sidebar.classList.remove('active');
        });
    });

    if (menuToggle) {
        menuToggle.addEventListener('click', () => sidebar.classList.toggle('active'));
    }

    document.addEventListener('click', e => {
        if (window.innerWidth <= 768 &&
            !sidebar.contains(e.target) &&
            !menuToggle.contains(e.target)) {
            sidebar.classList.remove('active');
        }
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
async function loadDashboard() {
    try {
        const res  = await fetch(`${API_BASE}/api/analytics/dashboard`, {credentials:'include'});
        const data = await res.json();
        if (!data.success) return;

        // Stat cards
        animateNumber(document.getElementById('statTotal'),   data.stats.totalEmails);
        animateNumber(document.getElementById('statThreats'), data.stats.threatsBlocked);
        animateNumber(document.getElementById('statSafe'),    data.stats.safeEmails);

        const pct = data.stats.totalEmails > 0
            ? ((data.stats.safeEmails / data.stats.totalEmails) * 100).toFixed(1)
            : 0;
        document.getElementById('statSafeChange').textContent   = `${pct}% safe rate`;
        document.getElementById('statThreatsChange').textContent =
            `${data.stats.dangerous || 0} high risk detected`;

        // Notification badge
        document.getElementById('notifBadge').textContent = data.stats.threatsBlocked || 0;

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
                label: 'Threats Detected',
                data: trend.data,
                borderColor: '#ef4444',
                backgroundColor: 'rgba(239,68,68,0.1)',
                tension: 0.4,
                fill: true
            }, {
                label: 'Safe Emails',
                data: trend.safe || trend.data.map(v => Math.max(0, v * 8)),
                borderColor: '#10b981',
                backgroundColor: 'rgba(16,185,129,0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { labels: { color: '#cbd5e1', font: { size: 12 } } } },
            scales: {
                y: { beginAtZero: true,
                    grid: { color: '#334155' }, ticks: { color: '#94a3b8' } },
                x: { grid: { color: '#334155' }, ticks: { color: '#94a3b8' } }
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
                    labels: { color: '#cbd5e1', font: { size: 12 }, padding: 15 }
                }
            }
        }
    });
}

// ============================================================
// EMAILS — load and render from backend
// ============================================================
async function loadEmails(filter = 'all') {
    const list = document.getElementById('emailList');
    const countEl = document.getElementById('emailCountInfo');
    list.innerHTML = `<div class="loading-state">
        <i class="fas fa-spinner fa-spin"></i><p>Loading emails...</p></div>`;

    try {
        const res  = await fetch(`/api/emails?filter=${filter}&limit=30`);
        const data = await res.json();
        if (!data.success) throw new Error(data.error);

        cachedEmails = data.emails;
        // FIX: populate safe lookup map
        data.emails.forEach(e => { emailDataMap[e.id] = e; });
        countEl.textContent = `${data.total} emails loaded`;

        if (data.emails.length === 0) {
            list.innerHTML = `<div class="empty-state">
                <i class="fas fa-inbox"></i><p>No emails found for this filter.</p></div>`;
            return;
        }

        renderEmailList(data.emails);

    } catch (err) {
        console.error('Email load error:', err);
        list.innerHTML = `<div class="empty-state error">
            <i class="fas fa-exclamation-circle"></i>
            <p>Could not load emails. <a onclick="loadEmails('all')" href="#">Retry</a></p></div>`;
    }
}

function renderEmailList(emails) {
    const list = document.getElementById('emailList');
    list.innerHTML = emails.map(email => {
        const level = email.threat?.level || 'safe';
        const icon  = { safe: 'fa-check-circle', suspicious: 'fa-exclamation-circle',
                        dangerous: 'fa-exclamation-triangle' }[level];
        const tags  = email.threat?.reasons?.slice(0, 2).map(r =>
            `<span class="tag">${escHtml(r.split(':')[0])}</span>`).join('') || '';
        const date  = email.date ? new Date(email.date).toLocaleTimeString([], {
            hour: '2-digit', minute: '2-digit' }) : '';

        // ── Scan data ─────────────────────────────────────────────
        const t       = email.threat || {};
        const authRaw = t.authDetails?.raw || '';

        // SPF / DKIM / DMARC
        const spf   = (authRaw.match(/spf=(pass|fail|softfail|neutral|none|permerror)/i)  ||[])[1]||'none';
        const dkim  = (authRaw.match(/dkim=(pass|fail|neutral|none|permerror)/i)           ||[])[1]||'none';
        const dmarc = (authRaw.match(/dmarc=(pass|fail|none)/i)                            ||[])[1]||'none';
        function chip(label, val) {
            const v = (val||'none').toLowerCase();
            const c = v==='pass'?'#10b981':(v==='fail'||v==='permerror')?'#ef4444':v==='softfail'?'#f59e0b':'#64748b';
            const i = v==='pass'?'✅':(v==='fail'||v==='permerror')?'❌':v==='softfail'?'⚠️':'➖';
            return `<span class="si-chip" style="border-color:${c};color:${c}">${i} ${label}: ${v.toUpperCase()}</span>`;
        }

        // URL scan
        const links   = email.links || [];
        const SUSP    = [/paypa1\.com/i,/g00gle\.com/i,/amaz0n\.com/i,/micros0ft\.com/i,
                         /secure-login\./i,/account-verify\./i,/login-confirm\./i,/verify-account\./i];
        const IP_PAT  = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}/;
        const badUrls = links.filter(u => SUSP.some(p=>p.test(u)) || IP_PAT.test(u));
        const urlColor = badUrls.length>0?'#ef4444':links.length>0?'#10b981':'#64748b';
        const urlText  = badUrls.length>0?`${badUrls.length} suspicious / ${links.length} total`
                       : links.length>0?`${links.length} scanned — clean`:'No links';

        // Attachment scan
        const atts     = email.attachments || [];
        const attDets  = t.attachmentDetails || [];
        const DANG     = new Set(['exe','bat','cmd','com','msi','ps1','vbs','js','jse','scr',
                                  'pif','hta','jar','lnk','url','zip','rar','7z','iso',
                                  'doc','docm','xls','xlsm','ppt','pptm']);
        const SUSP_EXT = new Set(['pdf','docx','xlsx','pptx','rtf']);
        const DBLEXT   = /\.\w{2,4}\.(exe|bat|cmd|scr|vbs|js|pif|com)$/i;
        let attSummaryColor = '#64748b', attSummaryIcon = '➖', attSummaryText = 'No attachments';
        let attChips = '';
        if (atts.length > 0) {
            const dangerCount = atts.filter(a => {
                const e = (a.filename||'').split('.').pop().toLowerCase();
                return DANG.has(e) || DBLEXT.test(a.filename||'');
            }).length;
            attSummaryColor = dangerCount>0?'#ef4444':'#10b981';
            attSummaryIcon  = dangerCount>0?'❌':'✅';
            attSummaryText  = `${atts.length} file${atts.length!==1?'s':''} — ${dangerCount>0?`${dangerCount} dangerous`:'all safe'}`;
            attChips = atts.map(att => {
                const name = att.filename||'unnamed';
                const ext  = name.split('.').pop().toLowerCase();
                const det  = attDets.find(d=>d.filename===name);
                const risk = det?.risk||(DBLEXT.test(name)?'dangerous':DANG.has(ext)?'dangerous':SUSP_EXT.has(ext)?'suspicious':'clean');
                const c    = risk==='dangerous'?'#ef4444':risk==='suspicious'?'#f59e0b':'#10b981';
                const ic   = risk==='dangerous'?'❌':risk==='suspicious'?'⚠️':'✅';
                return `<span class="si-chip" style="border-color:${c};color:${c}">${ic} ${escHtml(name.substring(0,20))}${name.length>20?'…':''}</span>`;
            }).join('');
        }

        // ── Full detail panel (hidden until toggle clicked) ───────
        const scanPanel = `
        <div class="scan-inline-panel" id="scan-panel-${email.id}" style="display:none">
            <div class="si-row">
                <span class="si-label">🔐 SPF / DKIM / DMARC</span>
                <div class="si-chips">
                    ${chip('SPF',spf)}${chip('DKIM',dkim)}${chip('DMARC',dmarc)}
                    ${!authRaw?'<span class="si-note">No auth headers — heuristic used</span>':''}
                </div>
            </div>
            <div class="si-row">
                <span class="si-label">🔗 URL Scanner</span>
                <div class="si-chips">
                    <span class="si-chip" style="border-color:${urlColor};color:${urlColor}">${links.length>0?'✅':'➖'} ${urlText}</span>
                    ${badUrls.slice(0,3).map(u=>`<span class="si-chip" style="border-color:#ef4444;color:#ef4444" title="${escHtml(u)}">⚠️ ${escHtml(u.replace(/https?:\/\//,'').substring(0,28))}…</span>`).join('')}
                </div>
            </div>
            <div class="si-row">
                <span class="si-label">📎 Attachments</span>
                <div class="si-chips">
                    <span class="si-chip" style="border-color:${attSummaryColor};color:${attSummaryColor}">${attSummaryIcon} ${attSummaryText}</span>
                    ${attChips}
                </div>
            </div>
        </div>`;

        // ── Status bar (always visible, shows 3 coloured dots) ────
        const spfDot = spf==='pass'?'#10b981':(spf==='fail'||spf==='permerror')?'#ef4444':spf==='softfail'?'#f59e0b':'#64748b';
        const statusBar = `
        <button class="btn-scan-toggle" id="scan-btn-${email.id}"
            onclick="toggleScanPanel('${email.id}')" title="Show scan results">
            <span class="scan-status-row">
                <span class="scan-status-item" style="color:${spfDot}">
                    <span class="scan-dot" style="background:${spfDot}"></span>
                    <span class="scan-status-text">SPF/DKIM/DMARC</span>
                </span>
                <span class="scan-status-sep">·</span>
                <span class="scan-status-item" style="color:${urlColor}">
                    <span class="scan-dot" style="background:${urlColor}"></span>
                    <span class="scan-status-text">URL${links.length>0?` (${links.length})`:'s'}</span>
                </span>
                <span class="scan-status-sep">·</span>
                <span class="scan-status-item" style="color:${attSummaryColor}">
                    <span class="scan-dot" style="background:${attSummaryColor}"></span>
                    <span class="scan-status-text">Files${atts.length>0?` (${atts.length})`:''}</span>
                </span>
                <span class="scan-toggle-arrow" id="scan-arrow-${email.id}">▾</span>
            </span>
        </button>`;

        return `<div class="email-item ${level}" data-id="${email.id}">
            <input type="checkbox" class="email-checkbox">
            <div class="email-status"><i class="fas ${icon}"></i></div>
            <div class="email-content">
                <div class="email-header">
                    <h4>${escHtml(email.subject)}</h4>
                    <span class="email-time">${date}</span>
                </div>
                <p class="email-sender">From: ${escHtml(email.from)}</p>
                <p class="email-preview">${escHtml(email.snippet)}</p>
                ${tags ? `<div class="threat-tags">${tags}</div>` : ''}
                ${statusBar}
                ${scanPanel}
            </div>
            <button class="btn-icon ${level === 'dangerous' ? 'danger' : ''}"
                onclick="openEmailModal('${email.id}')" title="View Details">
                <i class="fas ${level === 'dangerous' ? 'fa-shield-alt' : 'fa-eye'}"></i>
            </button>
        </div>`;
    }).join('');

    initSelectAll();
    initSearchFilter();
}

function toggleScanPanel(emailId) {
    const panel = document.getElementById(`scan-panel-${emailId}`);
    const btn   = document.getElementById(`scan-btn-${emailId}`);
    const arrow = document.getElementById(`scan-arrow-${emailId}`);
    if (!panel) return;
    const isOpen = panel.style.display !== 'none';
    panel.style.display = isOpen ? 'none' : 'block';
    btn.classList.toggle('active', !isOpen);
    if (arrow) arrow.style.transform = isOpen ? 'rotate(0deg)' : 'rotate(180deg)';
}

// ============================================================
// THREATS — load from backend
// ============================================================
async function loadThreats() {
    const detailsEl = document.getElementById('detailedThreats');
    detailsEl.innerHTML = `<div class="loading-state">
        <i class="fas fa-spinner fa-spin"></i><p>Analysing threats...</p></div>`;

    try {
        const res  = await fetch(`${API_BASE}/api/threats`, {credentials:'include'});
        const data = await res.json();
        if (!data.success) throw new Error(data.error);

        // Category counts
        const { summary } = data;
        const total = summary.total || 1;

        // Simple category split from reasons keywords
        let phishing = 0, malware = 0, spoofing = 0, other = 0;
        data.threats.forEach(t => {
            const reasons = (t.threat?.reasons || []).join(' ').toLowerCase();
            if (reasons.includes('phishing') || reasons.includes('keyword'))  phishing++;
            else if (reasons.includes('link') || reasons.includes('url'))     malware++;
            else if (reasons.includes('domain') || reasons.includes('bank'))  spoofing++;
            else                                                               other++;
        });

        const pct = n => total ? `${((n / total) * 100).toFixed(1)}%` : '0%';
        document.getElementById('catPhishing').textContent   = phishing;
        document.getElementById('catPhishingPct').textContent = pct(phishing);
        document.getElementById('catMalware').textContent    = malware;
        document.getElementById('catMalwarePct').textContent  = pct(malware);
        document.getElementById('catSpoofing').textContent   = spoofing;
        document.getElementById('catSpoofingPct').textContent = pct(spoofing);
        document.getElementById('catOther').textContent      = other;
        document.getElementById('catOtherPct').textContent    = pct(other);

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

            return `<div class="threat-detail-card" id="threat-${email.id}">
                <div class="threat-detail-header">
                    <div class="threat-severity ${sevCls}">${sev}</div>
                    <span class="threat-date">${email.date || ''}</span>
                </div>
                <h3>${escHtml(email.subject)}</h3>
                <div class="threat-info-grid">
                    <div class="info-item">
                        <label>From:</label>
                        <span>${escHtml(email.from)}</span>
                    </div>
                    <div class="info-item">
                        <label>Threat Score:</label>
                        <span>${t.score}/100</span>
                    </div>
                    <div class="info-item">
                        <label>Reasons:</label>
                        <span>${(t.reasons || []).slice(0,2).join('; ') || 'N/A'}</span>
                    </div>
                    <div class="info-item">
                        <label>Links Found:</label>
                        <span>${email.links?.length || 0} detected</span>
                    </div>
                </div>
                <div class="threat-actions">
                    <button class="btn btn-secondary"
                        onclick="openEmailModal('${email.id}')">View Email</button>
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

function openEmailModal(emailId) {
    const email = emailDataMap[emailId] || cachedEmails.find(e => e.id === emailId);
    if (!email) { showToast('Error', 'Email not found — try clicking Scan Now first', 'warning'); return; }

    const modal     = document.getElementById('emailModal');
    const bodyEl    = document.getElementById('modalBody');
    const subjectEl = document.getElementById('modalSubject');
    const hpBtn     = document.getElementById('modalEngageHoneypot');

    subjectEl.textContent = email.subject;

    const t = email.threat;
    const levelColor = { safe:'var(--success-color)', suspicious:'var(--warning-color)',
                         dangerous:'var(--danger-color)' }[t?.level] || 'var(--text-muted)';

    bodyEl.innerHTML = `
        <div class="modal-email-meta">
            <div class="modal-meta-row"><strong>From:</strong> ${escHtml(email.from)}</div>
            <div class="modal-meta-row"><strong>To:</strong> ${escHtml(email.to)}</div>
            <div class="modal-meta-row"><strong>Date:</strong> ${email.date}</div>
            <div class="modal-meta-row">
                <strong>Threat Level:</strong>
                <span style="color:${levelColor};font-weight:600;text-transform:capitalize;">
                    ${t?.level || 'safe'} (Score: ${t?.score || 0}/100)
                </span>
            </div>
        </div>
        ${t?.reasons?.length ? `
        <div class="modal-threats">
            <strong>⚠️ Threat Reasons:</strong>
            <ul>${t.reasons.map(r => `<li>${escHtml(r)}</li>`).join('')}</ul>
        </div>` : ''}
        ${email.links?.length ? `
        <div class="modal-links">
            <strong>🔗 Links Found (${email.links.length}):</strong>
            <ul>${email.links.slice(0,5).map(l =>
                `<li style="word-break:break-all;font-size:12px;color:var(--warning-color)">${escHtml(l)}</li>`
            ).join('')}</ul>
        </div>` : ''}
        <div class="modal-body-text">
            <strong>Preview:</strong>
            <p>${escHtml(email.snippet)}</p>
        </div>`;

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
        await fetch(`${API_BASE}/api/settings`, {
            method: 'PUT', credentials: 'include',
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
        const res  = await fetch(`${API_BASE}/api/honeypot/engage`, {
            method: 'POST', credentials: 'include',
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
            await loadHoneypotSessions();
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

async function loadHoneypotSessions() {
    const list = document.getElementById('honeypotSessionsList');

    try {
        const res  = await fetch(`${API_BASE}/api/honeypot/sessions`, {credentials:'include'});
        const data = await res.json();

        document.getElementById('hpActiveSessions').textContent = data.totalSessions || 0;
        document.getElementById('hpTimeWasted').textContent = `${data.totalMinutesWasted || 0} min`;
        // FIX 2: use victimsProtected from backend (scoped to this user), not a made-up formula
        document.getElementById('hpVictims').textContent = data.victimsProtected || 0;

        if (!data.sessions || data.sessions.length === 0) {
            list.innerHTML = `<div class="empty-state">
                <i class="fas fa-bug"></i>
                <p>No active sessions. Enable Honeypot Mode and click "Engage Honeypot" on a threat.</p>
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
                <div class="session-details">
                    <p><strong>Scammer Email:</strong> ${escHtml(s.senderEmail)}</p>
                    <p><strong>Replies Sent:</strong> ${s.repliesSent}</p>
                    <p><strong>Started:</strong> ${new Date(s.startedAt).toLocaleString()}</p>
                </div>
                <div class="session-actions">
                    <!-- FIX 4: pass sessionId (not emailId) to match the DELETE route -->
                    <button class="btn btn-sm btn-danger"
                        onclick="endHoneypotSession('${s.sessionId}')">End Session</button>
                </div>
            </div>`).join('');

    } catch (err) {
        list.innerHTML = `<div class="empty-state error">
            <i class="fas fa-exclamation-circle"></i><p>Could not load sessions.</p></div>`;
    }
}

async function endHoneypotSession(sessionId) {
    if (!confirm('End this honeypot session?')) return;

    // FIX 3: use sessionId (not emailId) to match the DELETE route in honeypot.js
    const res  = await fetch(`${API_BASE}/api/honeypot/sessions/${sessionId}`, { method: 'DELETE', credentials: 'include' });
    const data = await res.json();

    if (data.success) {
        showToast('Session Ended', 'Honeypot session closed successfully', 'success');
        await loadHoneypotSessions();
    }
}

async function blockThreat(emailId) {
    if (!confirm('Block this sender and delete the email?')) return;
    const card = document.getElementById(`threat-${emailId}`);
    if (card) {
        card.style.opacity = '0.4';
        setTimeout(() => card.remove(), 600);
    }
    showToast('Blocked', 'Sender has been blocked', 'success');
}

// ============================================================
// SETTINGS
// ============================================================
function initSettings() {
    // Load saved settings from backend
    fetch(`${API_BASE}/api/settings`).then(r => r.json()).then(data => {
        if (!data.success) return;
        const settings = data.settings;

        document.querySelectorAll('[data-setting]').forEach(input => {
            const key = input.dataset.setting;
            if (key in settings) input.checked = settings[key];
        });

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
            const key   = this.dataset.setting;
            const value = this.checked;

            await fetch(`${API_BASE}/api/settings`, {
                method: 'PUT', credentials: 'include',
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

    document.getElementById('reconnectGmail')?.addEventListener('click', function () {
        window.location.href = `${API_BASE}/auth/google`;
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
            loadEmails(this.dataset.filter);
        });
    });
}

// ============================================================
// SEARCH (client-side filter on cached emails)
// ============================================================
function initSearchFilter() {
    const searchInput = document.getElementById('searchInput');
    if (!searchInput) return;

    searchInput.addEventListener('input', function () {
        const term   = this.value.toLowerCase();
        const items  = document.querySelectorAll('.email-item');
        items.forEach(item => {
            const text = item.textContent.toLowerCase();
            item.style.display = text.includes(term) ? 'flex' : 'none';
        });
    });
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

        await loadEmails('all');
        await loadDashboard();
        await loadThreats();

        icon.style.animation = '';
        this.disabled = false;
        showToast('Scan Complete', `Inbox rescanned. Dashboard updated.`, 'success');
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
            const response = await fetch(`${API_BASE}/api/threats/report`, {credentials:'include'});

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
// LOGIN PORTAL — Tab switching + Admin login
// =============================================================

function switchLoginTab(role) {
    // Toggle tab buttons
    document.getElementById('tabUser').classList.toggle('active',  role === 'user');
    document.getElementById('tabAdmin').classList.toggle('active', role === 'admin');

    // Toggle panels
    document.getElementById('panelUser').classList.toggle('active',  role === 'user');
    document.getElementById('panelAdmin').classList.toggle('active', role === 'admin');

    // Clear error on switch
    const err = document.getElementById('adminLoginError');
    if (err) err.classList.remove('visible');
}

function toggleAdminPass() {
    const input = document.getElementById('adminLoginPass');
    const icon  = document.getElementById('passIcon');
    if (input.type === 'password') {
        input.type   = 'text';
        icon.className = 'fas fa-eye-slash';
    } else {
        input.type   = 'password';
        icon.className = 'fas fa-eye';
    }
}

async function doAdminLogin() {
    const email    = (document.getElementById('adminLoginEmail')?.value || '').trim();
    const password = document.getElementById('adminLoginPass')?.value || '';
    const errorEl  = document.getElementById('adminLoginError');
    const btn      = document.getElementById('btnAdminLogin');

    if (!email || !password) {
        errorEl.textContent = 'Please enter both email and password.';
        errorEl.classList.add('visible');
        return;
    }

    // Loading state
    btn.disabled   = true;
    btn.innerHTML  = '<i class="fas fa-spinner fa-spin"></i> Signing in...';
    errorEl.classList.remove('visible');

    try {
        const res  = await fetch(`${API_BASE}/admin/api/login`, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ email, password })
        });
        const data = await res.json();

        if (data.success) {
            // Redirect to admin panel
            window.location.href = '/admin';
        } else {
            errorEl.innerHTML = '<i class="fas fa-exclamation-circle"></i> Invalid credentials. Please try again.';
            errorEl.classList.add('visible');
            btn.disabled  = false;
            btn.innerHTML = '<i class="fas fa-sign-in-alt"></i> Sign in as Admin';
        }
    } catch (err) {
        errorEl.innerHTML = '<i class="fas fa-exclamation-circle"></i> Server error. Is the backend running?';
        errorEl.classList.add('visible');
        btn.disabled  = false;
        btn.innerHTML = '<i class="fas fa-sign-in-alt"></i> Sign in as Admin';
    }
}

// =============================================================
// NOTIFICATION PANEL — Real alerts from database
// =============================================================

async function loadNotifications() {
    try {
        const res  = await fetch(`${API_BASE}/api/notifications`, {credentials:'include'});
        const data = await res.json();
        if (!data.success) return;

        const badge = document.getElementById('notifBadge');
        if (badge) {
            badge.textContent = data.count || 0;
            badge.style.display = data.count > 0 ? 'flex' : 'none';
        }

        renderNotifications(data.alerts || []);
    } catch (err) {
        console.warn('Notification load error:', err.message);
    }
}

function renderNotifications(alerts) {
    const list = document.getElementById('notifList');
    if (!list) return;

    if (alerts.length === 0) {
        list.innerHTML = `<div class="notif-empty">
            <i class="fas fa-bell-slash"></i>
            <p>No new notifications.<br>Your inbox looks clean!</p>
        </div>`;
        return;
    }

    list.innerHTML = alerts.map(a => {
        const level   = a.alert_type || 'suspicious';
        const icon    = level === 'dangerous' ? 'fa-exclamation-circle' : 'fa-exclamation-triangle';
        const subject = a.subject || a.message || 'Threat detected';
        const sender  = a.sender_email || '';
        const time    = a.created_at
            ? new Date(a.created_at).toLocaleString('en-GB',{dateStyle:'short',timeStyle:'short'})
            : '';

        return `<div class="notif-item unread ${level}" onclick="closeNotifPanel()">
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

function openNotifPanel() {
    document.getElementById('notifPanel')?.classList.add('open');
    document.getElementById('notifOverlay')?.classList.add('open');
}

function closeNotifPanel() {
    document.getElementById('notifPanel')?.classList.remove('open');
    document.getElementById('notifOverlay')?.classList.remove('open');
}

async function markAllRead() {
    try {
        await fetch(`${API_BASE}/api/notifications/read`, { method: 'PUT' });
        const badge = document.getElementById('notifBadge');
        if (badge) { badge.textContent = '0'; badge.style.display = 'none'; }
        renderNotifications([]);
        showToast('Done', 'All notifications marked as read', 'success');
    } catch (err) {
        showToast('Error', 'Could not mark notifications as read', 'danger');
    }
}

// Override the notification button to open panel instead of switching page
document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('notificationBtn');
    if (btn) {
        // Remove old listener by cloning
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

        const res  = await fetch(`${API_BASE}/api/ai/chat`, {
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
        const res  = await fetch(`${API_BASE}/api/ai/summarise`, {
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
// Patch into the existing checkAuthAndInit flow
const _origCheckAuth = checkAuthAndInit;
// We do this safely by hooking into the welcome toast timing
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
        const res  = await fetch(`${API_BASE}/api/honeypot/poll`, { method: 'POST' });
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

function stopHoneypotPolling() {
    if (honeypotPollInterval) {
        clearInterval(honeypotPollInterval);
        honeypotPollInterval = null;
    }
}

// Start polling automatically when app loads
setTimeout(startHoneypotPolling, 5000);
