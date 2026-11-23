// worker.js — Genjutsu Cloudflare Worker
// Serves the static frontend via env.ASSETS and forwards /admin, /auth and /api
// to the Express backend.
//
// Two backends, free failover:
//   env.BACKEND_HOST  main server   (e.g. Koyeb)
//   env.BACKUP_HOST   backup server (e.g. Render) — optional
// Both run the same code and share one database (sessions included), so either
// can answer any request. If the main server errors, says it is unavailable or
// is too slow to answer, the request is sent to the backup instead, and the main
// server is skipped for a short while so later requests don't wait on it.

const BACKEND_PREFIXES = ['/admin', '/auth', '/api'];

// How long to wait for a server before trying the other one. A sleeping free
// server can take a while to wake, so the backup (last resort) gets longer.
const FIRST_TRY_MS = 20000;
const LAST_TRY_MS  = 70000;
const SKIP_DOWN_MS = 60000;          // skip a server that just failed, for 1 minute
const MAX_BUFFERED_BODY = 10 * 1024 * 1024;

const downUntil = new Map();         // host -> time it may be tried again (per worker instance)

// Responses that come from the hosting platform, not from Genjutsu itself:
// the app never handled the request, so sending it again elsewhere is safe.
const PLATFORM_DOWN = new Set([502, 503, 504, 520, 521, 522, 523, 524, 530]);

function hostsInOrder(env) {
  const hosts = [env.BACKEND_HOST, env.BACKUP_HOST]
    .map(h => (h || '').trim().replace(/\/$/, ''))
    .filter(Boolean)
    .filter((h, i, a) => a.indexOf(h) === i);
  const now = Date.now();
  const up   = hosts.filter(h => (downUntil.get(h) || 0) <= now);
  const down = hosts.filter(h => (downUntil.get(h) || 0) >  now);
  return [...up, ...down];           // servers that recently failed go last, never dropped
}

async function forward(host, url, request, body, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort('timeout'), timeoutMs);
  try {
    return await fetch(new Request(host + url.pathname + (url.search || ''), {
      method:   request.method,
      headers:  request.headers,
      body,
      redirect: 'manual',
      signal:   controller.signal,
    }));
  } finally {
    clearTimeout(timer);
  }
}

function passThrough(resp, host) {
  // Pass redirects (e.g. OAuth callbacks) straight through to the browser,
  // keeping every cookie the backend set.
  if (resp.status >= 300 && resp.status < 400) {
    const headers = new Headers({ 'Location': resp.headers.get('location') || '/' });
    for (const c of (resp.headers.getSetCookie?.() || [])) headers.append('Set-Cookie', c);
    if (![...headers.keys()].includes('set-cookie') && resp.headers.get('set-cookie')) {
      headers.set('Set-Cookie', resp.headers.get('set-cookie'));
    }
    headers.set('X-Genjutsu-Server', new URL(host).hostname.split('.')[0]);
    return new Response(null, { status: resp.status, headers });
  }
  const out = new Response(resp.body, resp);
  out.headers.set('X-Genjutsu-Server', new URL(host).hostname.split('.')[0]);
  return out;
}

function unavailable(request, url) {
  const wantsPage = request.method === 'GET' && (request.headers.get('accept') || '').includes('text/html');
  if (!wantsPage) {
    return new Response(JSON.stringify({ success: false, error: 'Genjutsu is waking up. Please try again in a minute.' }), {
      status: 503, headers: { 'Content-Type': 'application/json', 'Retry-After': '30', 'Cache-Control': 'no-store' }
    });
  }
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="20">
<title>Genjutsu is waking up</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;font:16px/1.5 system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0}
main{max-width:420px;padding:32px;text-align:center}h1{font-size:22px;margin:0 0 8px}p{color:#94a3b8;margin:0 0 20px}
.dot{width:12px;height:12px;border-radius:50%;background:#3b82f6;margin:0 auto 20px;animation:p 1.2s ease-in-out infinite}
@keyframes p{50%{opacity:.25;transform:scale(.7)}}@media (prefers-reduced-motion:reduce){.dot{animation:none}}
a{color:#93c5fd}</style></head><body><main><div class="dot" aria-hidden="true"></div>
<h1>Genjutsu is waking up</h1><p>Our servers were resting. This page will try again by itself in a few seconds.</p>
<a href="${url.pathname}${url.search}">Try now</a></main></body></html>`;
  return new Response(html, { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Retry-After': '20', 'Cache-Control': 'no-store' } });
}

async function proxy(request, env, url) {
  const hosts = hostsInOrder(env);
  if (!hosts.length) return new Response('Backend not configured', { status: 500 });

  const safeToRepeat = ['GET', 'HEAD', 'OPTIONS'].includes(request.method);
  let body;
  if (!['GET', 'HEAD'].includes(request.method)) {
    // Keep a copy of the body so it can be sent to the backup if needed
    const len = parseInt(request.headers.get('content-length') || '0', 10);
    body = len > MAX_BUFFERED_BODY ? request.body : await request.arrayBuffer();
  }
  const canResend = body === undefined || body instanceof ArrayBuffer;

  for (let i = 0; i < hosts.length; i++) {
    const host = hosts[i];
    const last = i === hosts.length - 1;
    try {
      const resp = await forward(host, url, request, body, last ? LAST_TRY_MS : FIRST_TRY_MS);
      if (PLATFORM_DOWN.has(resp.status) && !last && canResend) {
        downUntil.set(host, Date.now() + SKIP_DOWN_MS);
        continue;                       // the app never saw it: try the other server
      }
      if (resp.status < 500) downUntil.delete(host);
      return passThrough(resp, host);
    } catch (err) {
      downUntil.set(host, Date.now() + SKIP_DOWN_MS);
      const timedOut = String(err?.message || err).includes('timeout') || err?.name === 'AbortError';
      // A timed-out change (POST etc.) might still have happened on the slow
      // server, so only repeat it elsewhere when it is safe to.
      if (!last && canResend && (safeToRepeat || !timedOut)) continue;
      return unavailable(request, url);
    }
  }
  return unavailable(request, url);
}

// ── Wake-up pings ────────────────────────────────────────────
// Free Render servers sleep after ~15 minutes idle and take ~50s to boot.
// A Cloudflare cron (see wrangler.toml) pings every 10 minutes so the backend
// usually never falls asleep; page visits also poke it (see script.js).
let lastWake = 0;
function wakeBackends(env) {
  const hosts = [env.BACKEND_HOST, env.BACKUP_HOST]
    .map(h => (h || '').trim().replace(/\/$/, '')).filter(Boolean);
  return Promise.allSettled(hosts.map(h =>
    fetch(h + '/api/health', { headers: { 'User-Agent': 'genjutsu-wake' }, signal: AbortSignal.timeout(70000) })
  ));
}

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(wakeBackends(env));
  },

  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Page visit that reaches the Worker → wake the backend (at most every 30s)
    const isPage = request.method === 'GET' && (request.headers.get('accept') || '').includes('text/html');
    if (isPage && Date.now() - lastWake > 30000) {
      lastWake = Date.now();
      ctx.waitUntil(wakeBackends(env));
    }

    if (BACKEND_PREFIXES.some(prefix => url.pathname === prefix || url.pathname.startsWith(prefix + '/'))) {
      return proxy(request, env, url);
    }

    // ── Static assets (frontend) ──────────────────────────────
    try {
      return await env.ASSETS.fetch(request);
    } catch {
      // SPA fallback — any unmatched path serves index.html
      const indexUrl = new URL('/index.html', url.origin);
      return await env.ASSETS.fetch(new Request(indexUrl.toString(), request));
    }
  }
};
