// services/geo.js — where an email was sent from.
// Reads the sending server's IP from the Received / X-Originating-IP headers and
// looks up its country in an offline database (geoip-country). No IP leaves the server.
// It's a hint, not proof: scammers can send through VPNs, hosting or big webmail providers.
let geoip = null;
try { geoip = require('geoip-country'); } catch (_) { /* optional */ }

function isPublicIp(ip) {
  if (!ip) return false;
  if (ip.includes(':')) {                         // IPv6
    const l = ip.toLowerCase();
    return !(l === '::1' || l.startsWith('fe80') || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('::ffff:127.'));
  }
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(n => !(n >= 0 && n <= 255))) return false;
  const [a, b] = p;
  return !(a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
           (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224);
}

const IPV4 = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/;
const IPV6 = /\b((?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4})\b/i;
function ipIn(text) {
  const br = String(text).match(/[[(]\s*(?:IPv6:)?([0-9a-f.:]+)\s*[\])]/gi) || [];
  for (const m of br) { const ip = m.replace(/^[[(]\s*(?:IPv6:)?|\s*[\])]$/gi, ''); if ((IPV4.test(ip) || IPV6.test(ip)) && isPublicIp(ip)) return ip; }
  return null;
}

// received: array of Received header values, top (newest) first
function originIp({ received = [], xOriginatingIp = '' } = {}) {
  const x = String(xOriginatingIp || '').replace(/[[\]\s]/g, '');
  if (x && isPublicIp(x)) return x;
  for (const r of received) {
    if (!/^\s*from\s/i.test(r)) continue;
    const ip = ipIn(r);
    if (ip) return ip;
  }
  return null;
}

function countryOf(ip) {
  if (!geoip || !ip || !isPublicIp(ip)) return null;
  try { const g = geoip.lookup(ip); return g ? { code: g.country, name: g.name || g.country } : null; } catch (_) { return null; }
}

module.exports = { isPublicIp, originIp, countryOf };
