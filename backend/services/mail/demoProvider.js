// ============================================================
// services/mail/demoProvider.js — a pretend mailbox for demo mode
// ------------------------------------------------------------
// Lets anyone try Genjutsu without signing in. Nothing is sent and
// no real mailbox is touched; blocking and replies are simulated.
// ============================================================
const name  = 'demo';
const label = 'Demo mailbox';
const hasServerFilters = true;

const PASS = 'mx.google.com; spf=pass smtp.mailfrom=x; dkim=pass header.i=@x; dmarc=pass header.from=x';
const FAIL = 'mx.google.com; spf=fail smtp.mailfrom=x; dkim=none; dmarc=fail header.from=x';
const ago = (h) => new Date(Date.now() - h * 3600 * 1000).toISOString();

const SAMPLES = () => [
  { id: 'demo-1', from: 'PayPal Security <service@paypa1-support.co>', subject: 'Your account has been limited', date: ago(2), authResults: FAIL,
    body: 'Dear customer,\n\nWe noticed unusual activity on your account. Your account has been limited.\nVerify your account within 24 hours or it will be permanently closed:\nhttp://paypa1-verify.co/login\n\nPayPal Security Team',
    links: ['http://paypa1-verify.co/login'], scam: true },
  { id: 'demo-2', from: 'Accounts <billing@acme-supplies.com>', replyTo: 'acme.billing.dept@gmail.com', subject: 'Updated bank details for invoice #4471', date: ago(5), authResults: PASS,
    body: 'Hi,\n\nPlease note the change of bank details for all future payments. Kindly send the payment for invoice #4471 to the new account today, as the old one is closed.\n\nAre you available? Please keep this confidential.\n\nRegards,\nAccounts', links: [], scam: true },
  { id: 'demo-3', from: 'Nabil Alerts <alert@nabil-notify.info>', subject: 'Your e-statement is ready', date: ago(9), authResults: FAIL,
    body: 'Your e-statement is ready. Log in at www.nabilbank.com to view it.',
    html: '<p>Your e-statement is ready. Log in at <a href="http://login-secure.xyz/nabil">www.nabilbank.com</a> to view it.</p>',
    links: ['http://login-secure.xyz/nabil'], scam: true },
  { id: 'demo-4', from: 'HR Department <hr@company-payroll.net>', subject: 'Salary revision letter', date: ago(20), authResults: PASS,
    body: 'Please open the attached salary revision letter and confirm by end of day.', attachments: [{ filename: 'Salary_Revision.pdf.exe', mimeType: 'application/octet-stream', size: 52000, demoFile: 'exe' }], links: [] },
  { id: 'demo-5', from: 'Neon <product@email.neon.tech>', subject: 'Welcome to Neon. Set up your coding agent', date: ago(26), authResults: PASS, listUnsubscribe: '<https://track.customer.io/unsubscribe/x>',
    body: 'Hi there,\n\nWelcome to Neon! Your project is ready.\nAlert: the Free plan includes 0.5 GB of storage per project.\n\nSet up your coding agent: https://neon.com/get-started\nRead the docs: https://neon.com/docs\nJoin us on Discord: https://discord.com/invite/neon\nPricing: https://neon.com/pricing\nStartups: https://neon.com/startups\nBlog: https://neon.com/blog\n\nThe Neon team',
    links: ['https://neon.com/get-started', 'https://neon.com/docs', 'https://discord.com/invite/neon', 'https://neon.com/pricing', 'https://neon.com/startups', 'https://neon.com/blog', 'https://track.customer.io/unsubscribe/x'] },
  { id: 'demo-6', from: 'Google <no-reply@accounts.google.com>', subject: 'Security alert: new sign-in on Mac', date: ago(30), authResults: PASS,
    body: 'A new sign-in on Mac.\nIf this was you, you don’t need to do anything. If not, we’ll help you secure your account.', links: ['https://myaccount.google.com/notifications'] },
  { id: 'demo-7', from: 'Babypips <newsletter@babypips.com>', subject: 'The Dollar Falls Against Every Major After a Data Miss', date: ago(34), authResults: PASS, listUnsubscribe: '<mailto:unsub@babypips.com>',
    body: 'Here is what moved the markets today. Act now to catch the next move!', links: Array.from({ length: 8 }, (_, i) => `https://www.babypips.com/news/${i}`) },
  { id: 'demo-9', from: 'eSewa Support <support@esewa-wallet-np.com>', subject: 'Scan to keep your wallet active', date: ago(3), authResults: FAIL,
    body: 'Dear customer,\n\nYour eSewa wallet KYC is incomplete. Scan the QR code in the attached notice with your phone and finish verification today, or your wallet will be blocked.\n\neSewa Support',
    links: [], attachments: [{ filename: 'eSewa_KYC_Notice.png', mimeType: 'image/png', size: 4200, demoFile: 'qr' }] },
  { id: 'demo-10', from: 'Accounts <accounts@himal-suppliers.com.np>', subject: 'Invoice INV-2219 for October', date: ago(30), authResults: PASS,
    body: 'Hello,\n\nPlease find the October invoice attached. If the content does not show, click Enable Content at the top.\n\nRegards,\nAccounts',
    links: [], attachments: [{ filename: 'INV-2219.docm', mimeType: 'application/vnd.ms-word.document.macroEnabled.12', size: 9000, demoFile: 'macro' }] },
  { id: 'demo-8', from: 'Sita Sharma <sita.sharma@college.edu.np>', subject: 'Notes for Thursday’s class', date: ago(48), authResults: PASS,
    body: 'Hi,\n\nSharing the notes for Thursday. See you in class!\n\nSita', links: [] }
].map(e => ({ ...e, authResults: e.authResults.replace(/=x\b/g, '=' + ((e.from.match(/@([^>]+)>/) || [])[1] || 'x')).replace(/@x\b/g, '@' + ((e.from.match(/@([^>]+)>/) || [])[1] || 'x')) }))
  .map(e => ({ threadId: e.id, messageId: `<${e.id}@demo.genjutsu>`, to: 'you@demo.genjutsu', snippet: e.body.replace(/\s+/g, ' ').slice(0, 120), labels: ['INBOX'], attachments: [], html: '', ...e }));

// Sample attachment bytes for the attachment check, made on request (never real malware)
function tinyZip(files) {
  const zlib = require('zlib');
  const locals = [], centrals = []; let off = 0;
  for (const [name, content] of Object.entries(files)) {
    const data = Buffer.from(content), comp = zlib.deflateRawSync(data), nm = Buffer.from(name), crc = zlib.crc32(data);
    const lh = Buffer.alloc(30); lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(8, 8); lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(nm.length, 26);
    const ch = Buffer.alloc(46); ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(8, 10); ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(comp.length, 20); ch.writeUInt32LE(data.length, 24); ch.writeUInt16LE(nm.length, 28); ch.writeUInt32LE(off, 42);
    locals.push(lh, nm, comp); centrals.push(ch, nm); off += 30 + nm.length + comp.length;
  }
  const cd = Buffer.concat(centrals), end = Buffer.alloc(22), n = Object.keys(files).length;
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(n, 8); end.writeUInt16LE(n, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cd, end]);
}
async function getAttachment(user, email, att) {
  if (att.demoFile === 'qr') return require('qrcode').toBuffer('http://esewa-kyc.top/verify', { type: 'png', margin: 2, width: 300 });
  if (att.demoFile === 'macro') return tinyZip({ '[Content_Types].xml': '<Types/>', 'word/document.xml': '<w:document/>', 'word/vbaProject.bin': 'Attribute VB_Name = "Invoice"\nSub AutoOpen()\nEnd Sub' });
  if (att.demoFile === 'exe') return Buffer.concat([Buffer.from('MZ'), Buffer.alloc(256)]);   // just the "this is a program" header
  return null;
}

const state = new Map();          // userId -> { spam:Set, replies:{sender:count}, sent:[] }
const st = (user) => { if (!state.has(user.id)) state.set(user.id, { spam: new Set(), replies: {}, sent: [] }); return state.get(user.id); };

async function fetchEmails(user, maxResults = 50) {
  const s = st(user);
  return SAMPLES().filter(e => !s.spam.has(e.id)).slice(0, maxResults);
}
async function sendReply(user, to, subject, body) { st(user).sent.push({ to, subject, body, at: Date.now() }); return { demo: true }; }
async function moveToSpam(user, id)     { st(user).spam.add(id); }
async function removeFromSpam(user, id) { st(user).spam.delete(id); }
async function createSpamFilter()       { return { demo: true }; }
async function forwardAsAttachment()    { return { demo: true }; }

// Simulated scammer: answers Nami a few times, 20 seconds after each reply
const SCAMMER_LINES = [
  'Thank you for your quick reply. To restore access you must pay a small verification fee of $49. Send it by Western Union or to USDT wallet TQrY8tryqsYVCYS3MFbtffiPp2ccyn4STm.',
  'Please hurry, your account will be closed today. You can also call our agent on WhatsApp +977 9812345678 or Telegram @fastrefund_desk.',
  'Sir/Madam we cannot wait any longer. Just click the link http://paypa1-verify.co/pay and enter your card details now.'
];
async function findLatestFrom(user, sender, { afterMs = 0 } = {}) {
  const s = st(user);
  const key = String(sender || '').toLowerCase();
  const n = s.replies[key] || 0;
  if (n >= SCAMMER_LINES.length || Date.now() < afterMs + 20000) return null;
  s.replies[key] = n + 1;
  return { id: `demo-reply-${n + 1}`, messageId: `<demo-reply-${n + 1}@demo.genjutsu>`, text: SCAMMER_LINES[n], date: new Date().toISOString() };
}

module.exports = { name, label, hasServerFilters, getAttachment, fetchEmails, sendReply, moveToSpam, removeFromSpam, createSpamFilter, forwardAsAttachment, findLatestFrom };
