// worker.js — Genjutsu Cloudflare Worker
// Serves static frontend files via env.ASSETS (modern Workers Assets API)
// Proxies /admin, /auth, /api routes to the Express backend on Render

const BACKEND_PREFIXES = ['/admin', '/auth', '/api'];

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // ── Proxy backend routes ──────────────────────────────────
    // Any path starting with /admin, /auth, or /api goes straight
    // to the Express backend — never touches static assets.
    if (BACKEND_PREFIXES.some(prefix =>
      url.pathname === prefix || url.pathname.startsWith(prefix + '/')
    )) {
      const backendBase = (env.BACKEND_HOST || '').replace(/\/$/, '');
      const backendUrl  = backendBase + url.pathname + (url.search || '');

      const backendRequest = new Request(backendUrl, {
        method:   request.method,
        headers:  request.headers,
        body:     ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
        redirect: 'manual',
      });

      const backendResponse = await fetch(backendRequest);

      // Pass redirects (e.g. OAuth callbacks) straight through to the browser
      if (backendResponse.status >= 300 && backendResponse.status < 400) {
        return new Response(null, {
          status:  backendResponse.status,
          headers: {
            'Location':   backendResponse.headers.get('location') || '/',
            'Set-Cookie': backendResponse.headers.get('set-cookie') || ''
          }
        });
      }

      return backendResponse;
    }

    // ── Static assets (frontend) ──────────────────────────────
    // env.ASSETS is bound automatically by Wrangler when
    // `assets = { directory = "./" }` is set in wrangler.toml.
    // Falls back to index.html for SPA client-side routing.
    try {
      return await env.ASSETS.fetch(request);
    } catch {
      // SPA fallback — any unmatched path serves index.html
      const indexUrl = new URL('/index.html', url.origin);
      return await env.ASSETS.fetch(new Request(indexUrl.toString(), request));
    }
  }
};
