// Shared setup: no real database, mailbox or network is touched by the tests.
process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'test-secret';
process.env.DATABASE_URL = process.env.DATABASE_URL || 'postgres://test:test@127.0.0.1:1/test';
process.env.SAFE_BROWSING_API_KEY = '';
process.env.GROQ_API_KEY = '';
const path = require('path');
const ROOT = path.join(__dirname, '..');
const req = (p) => require(path.join(ROOT, p));
const NO_NET = { domainAge: false };
const PASS_AUTH = (d) => `spf=pass smtp.mailfrom=${d}; dkim=pass header.i=@${d}; dmarc=pass header.from=${d}`;
const FAIL_AUTH = 'spf=fail smtp.mailfrom=x; dkim=fail; dmarc=fail header.from=x';
module.exports = { ROOT, req, NO_NET, PASS_AUTH, FAIL_AUTH };
