// ============================================================
// services/digest.js — weekly security digest, sent to the
// user's own inbox from their own account.
// ============================================================
const db   = require('../database/db');
const mail = require('./mail');

function buildDigest(user, d) {
  const lines = [];
  lines.push(`Hi ${String(user.name || '').split(' ')[0] || 'there'},`, '');
  lines.push(`Here is what Genjutsu saw in your inbox over the last 7 days.`, '');
  lines.push(`  Emails checked:      ${d.total}`);
  lines.push(`  Dangerous:           ${d.dangerous}`);
  lines.push(`  Worth a look:        ${d.suspicious}`);
  lines.push(`  Quarantined:         ${d.quarantined}`);
  if (d.honeypotSessions) lines.push(`  Scammer time wasted: ${d.honeypotMinutes} min (${d.honeypotSessions} conversation${d.honeypotSessions === 1 ? '' : 's'})`);
  lines.push('');
  if (d.top.length) {
    lines.push('Emails to double-check:');
    d.top.forEach(t => lines.push(`  • ${t.subject || '(no subject)'}\n    from ${t.sender_email || 'unknown'} · score ${Math.round(t.confidence_score * 100)}/100`));
    lines.push('');
  } else {
    lines.push('Nothing dangerous got through this week. 🎉', '');
  }
  lines.push('Tip: real banks and services never ask for your password or a one-time code by email.', '');
  lines.push('Open Genjutsu to review or change these emails. You can turn this digest off in Settings.');
  const subject = d.dangerous
    ? `Genjutsu weekly: ${d.dangerous} dangerous email${d.dangerous === 1 ? '' : 's'} this week`
    : `Genjutsu weekly: your inbox looked safe this week`;
  return { subject, text: lines.join('\n') };
}

async function sendDigest(userId, sessionUser = null) {
  const user = sessionUser || await db.getStoredUser(userId);
  if (!user) throw new Error('User not found');
  const data = await db.getDigestData(userId);
  const { subject, text } = buildDigest(user, data);
  await mail.sendToSelf(user, subject, text);
  if (!sessionUser) { try { await db.saveStoredTokens(userId, user); } catch (_) {} }
  await db.markDigestSent(userId);
  await db.logUserActivity(userId, 'Weekly digest sent', subject);
  return { subject, data };
}

// Checks every hour for anyone whose digest is due
function startDigestScheduler() {
  const run = async () => {
    let due = [];
    try { due = await db.getUsersDueForDigest(); } catch (_) { return; }
    for (const userId of due) {
      try { await sendDigest(userId); }
      catch (err) { console.warn(`⚠️  Weekly digest failed for ${userId}:`, err.message); }
    }
  };
  setTimeout(run, 60 * 1000).unref();
  setInterval(run, 60 * 60 * 1000).unref();
}

module.exports = { buildDigest, sendDigest, startDigestScheduler };
