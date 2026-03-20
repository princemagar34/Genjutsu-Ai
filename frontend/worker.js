// worker.js — Genjutsu Cloudflare Worker
// Serves static frontend files (index.html, styles.css, script.js)

import { getAssetFromKV } from '@cloudflare/kv-asset-handler';
import manifestJSON from '__STATIC_CONTENT_MANIFEST';

const assetManifest = JSON.parse(manifestJSON);

export default {
  async fetch(request, env, ctx) {
    try {
      // Try to serve a static asset
      return await getAssetFromKV(
        { request, waitUntil: ctx.waitUntil.bind(ctx) },
        {
          ASSET_NAMESPACE: env.__STATIC_CONTENT,
          ASSET_MANIFEST:  assetManifest,
        }
      );
    } catch (e) {
      // For any unmatched route, serve index.html (SPA fallback)
      try {
        const indexRequest = new Request(
          new URL('/index.html', request.url).toString(),
          request
        );
        return await getAssetFromKV(
          { request: indexRequest, waitUntil: ctx.waitUntil.bind(ctx) },
          {
            ASSET_NAMESPACE: env.__STATIC_CONTENT,
            ASSET_MANIFEST:  assetManifest,
          }
        );
      } catch {
        return new Response('Not Found', { status: 404 });
      }
    }
  }
};
