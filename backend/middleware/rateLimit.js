// ============================================================
// middleware/rateLimit.js — simple per-user limits for the API
// In memory: fine for one server. Keyed by signed-in user, else IP.
// ============================================================
const buckets = new Map();

function rateLimit({ windowMs, max, name, message }) {
  return (req, res, next) => {
    const who = req.apiUser?.keyId || req.session?.user?.id || req.ip;
    const key = `${name}:${who}`;
    const now = Date.now();
    const hits = (buckets.get(key) || []).filter(t => now - t < windowMs);
    if (hits.length >= max) {
      const retry = Math.ceil((windowMs - (now - hits[0])) / 1000);
      res.set('Retry-After', String(retry));
      return res.status(429).json({ success: false, error: message || `Too many requests. Try again in ${retry} seconds.` });
    }
    hits.push(now);
    buckets.set(key, hits);
    next();
  };
}

// Tidy old entries every 10 minutes
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of buckets) if (!v.some(t => now - t < 60 * 60 * 1000)) buckets.delete(k);
}, 10 * 60 * 1000).unref();

module.exports = { rateLimit };
