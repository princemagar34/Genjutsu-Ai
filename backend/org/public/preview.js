// Sample data for the Super Admin's "Preview": the whole organization portal with nothing saved.
// Used only in the browser when the Genjutsu team picks "Preview (sample data)". Never sent to the server.
'use strict';
window.GJ_PREVIEW = (() => {
  const H = 36e5, now = Date.now(), at = (h) => new Date(now - h * H).toISOString();
  const members = [
    ['m1', 'principal@sample.edu.np', 'domain', 2, 3], ['m2', 'accounts@sample.edu.np', 'domain', 5, 6], ['m3', 'ram.sharma@gmail.com', 'list', 30, 30],
    ['m4', 'sita.teacher@sample.edu.np', 'domain', 1, 1], ['m5', 'hari.k@outlook.com', 'invite', 50, 49], ['m6', 'it@sample.edu.np', 'domain', 0.2, 0.3],
  ].map(([user_id, email, org_joined, login, scan]) => ({ user_id, email, org_joined, last_login: at(login), last_scan_at: at(scan), threats: 0 }));
  const blocked = [
    ['b1', 'm2', 'eSewa <support@esewa-wallet-np.com>', 'Your wallet will be blocked today', 'dangerous', 96, 3, ['Look-alike sender domain: esewa-wallet-np.com imitates esewa', 'QR code in "KYC.png" opens http://esewa-kyc.top/verify', 'Urgency: "blocked today"']],
    ['b2', 'm1', 'Ministry of Education <notice@moe-gov-np.top>', 'Revised salary scale 2083 (attached)', 'dangerous', 91, 9, ['Attachment "Salary-2083.docm" has macros that run by themselves', 'Sender pretends to be a government office from a .top domain']],
    ['b3', 'm3', 'Nabil Bank <alerts@nabil-alerts.info>', 'Unusual login on your account', 'dangerous', 88, 26, ['Display-name spoofing: says "Nabil" but sent from nabil-alerts.info', 'Link text shows nabilbank.com but goes to login-secure.xyz']],
    ['b4', 'm5', 'DHL Express <track@dhl-np-delivery.com>', 'Parcel on hold: customs fee Rs 450', 'suspicious', 58, 40, ['Asks for a small payment to release a parcel', 'Sender domain registered 6 days ago']],
    ['b5', 'm4', 'Principal <principal.sample.edu@gmail.com>', 'Quick favour, are you free?', 'suspicious', 47, 70, ['Uses the principal\'s name from a Gmail address', 'Classic gift-card scam opening']],
    ['b6', 'm2', 'Accounts Dept <billing@acme-supplies.com>', 'Our bank details have changed', 'suspicious', 52, 120, ['Reply-To goes to a different address (acme.billing@gmail.com)', '"Change of bank details" request']],
  ].map(([emailId, userId, senderEmail, subject, threatType, score, h, details]) => ({ emailId, userId, senderEmail, subject, threatType, score, scannedAt: at(h),
    userEmail: members.find(m => m.user_id === userId).email, details, overrideNote: null }));
  blocked.forEach(b => { members.find(m => m.user_id === b.userId).threats++; });
  const days = 14, labels = [], threats = [], safe = [];
  for (let i = days - 1; i >= 0; i--) {
    labels.push(new Date(now - i * 864e5).toLocaleDateString('en-GB', { day: '2-digit', month: 'short' }));
    threats.push(blocked.filter(b => Math.floor((now - Date.parse(b.scannedAt)) / 864e5) === i).length);
    safe.push(90 + ((i * 37) % 60));
  }
  const org = { org_id: 'preview', name: 'Sample School (preview)', domains: 'sample.edu.np', plan: 'free', plan_label: 'Free', status: 'active' };
  const data = {
    '/stats': { stats: { totalUsers: members.length, totalEmails: safe.reduce((a, b) => a + b, 0) + blocked.length, dangerousCount: 3, suspiciousCount: 3, totalHoneypot: 2, totalMinutesWasted: 95 } },
    '/trend': { trend: { labels, threats, safe } },
    '/blocked': { blocked, summary: { total: blocked.length } },
    '/org': { org, members, seatsUsed: members.length,
      invites: [{ code: 'sample-invite-code', url: `${location.origin}/?join=sample-invite-code`, uses: 1, max_uses: 50, expires_at: new Date(now + 12 * 864e5).toISOString() }],
      allowed: [{ email: 'ram.sharma@gmail.com', joined: true, added_at: at(60) }, { email: 'new.teacher@gmail.com', joined: false, added_at: at(5) }] },
    '/announcements': { announcements: [{ announcement_id: 'p1', message: 'Fake "salary update" emails are going around. Do not open the attachment.', level: 'warning', active: 1, created_at: at(8), expires_at: new Date(now + 6 * 864e5).toISOString() }] },
  };
  const emailsFor = (id) => {
    const mine = blocked.filter(b => b.userId === id).map(b => ({ subject: b.subject, sender_email: b.senderEmail, level: b.threatType, received_at: b.scannedAt, score: b.score, reasons: b.details }));
    const normal = ['Staff meeting moved to Friday', 'Exam timetable (final)', 'Your Daraz order has shipped', 'Re: Grade 9 science lab'].map((s, i) => ({ subject: s, sender_email: ['office@sample.edu.np', 'exam@sample.edu.np', 'no-reply@daraz.com.np', 'sita.teacher@sample.edu.np'][i], level: 'safe', received_at: at(4 + i * 11), score: 5 + i, reasons: [] }));
    const emails = [...mine, ...normal].sort((a, b) => Date.parse(b.received_at) - Date.parse(a.received_at));
    const counts = { dangerous: 0, suspicious: 0, safe: 0 }; emails.forEach(m => counts[m.level]++);
    return { total: emails.length, counts, emails };
  };
  return function answer(path, method) {
    if (method && method !== 'GET') throw new Error('This is a preview with sample data, so nothing can be changed. Create an organization to try it for real.');
    const p = path.split('?')[0];
    const m = p.match(/^\/users\/([^/]+)\/emails$/); if (m) return { success: true, ...emailsFor(decodeURIComponent(m[1])) };
    if (data[p]) return { success: true, ...JSON.parse(JSON.stringify(data[p])) };
    throw new Error('Not available in the preview.');
  };
})();
