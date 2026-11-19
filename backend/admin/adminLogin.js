// admin/adminLogin.js — admin sign-in (password + 2-step code), your own account security
const express = require('express');
const QRCode  = require('qrcode');
const auth    = require('./adminAuth');
const adb     = require('../database/adminDb');
const { seal, open } = require('../services/mail/secretBox');
const { logActivity, updateAdminLastLogin } = require('../database/db');
const { IDLE_MS, getIP, requireAdmin, sessionFor } = require('./adminCore');

const router = express.Router();
const lockKeys = (req, email) => [`e:${String(email || '').toLowerCase()}`, `ip:${getIP(req)}`];
const lockMsg  = (ms) => `Too many wrong tries. Try again in ${Math.ceil(ms / 60000)} minute${ms > 60000 ? 's' : ''}.`;
const log = (...a) => logActivity(...a).catch(() => {});

async function finishLogin(req, admin) {
  auth.clearFails(lockKeys(req, admin.email));
  await updateAdminLastLogin(admin.email);
  req.session.admin = sessionFor(admin);
  delete req.session.pendingAdmin;
  const ua = req.headers['user-agent'] || '';
  const label = auth.deviceLabel(ua);
  const isNew = await adb.seenDevice(admin.email, auth.sha256(ua), label, getIP(req)).catch(() => false);
  await log(admin.email, admin.role, 'LOGIN', `Admin logged in${admin.totp_enabled ? ' with 2-step code' : ''} · ${label}`, getIP(req));
  if (isNew) {
    await log(admin.email, admin.role, 'NEW_DEVICE_LOGIN', `Login from a new device: ${label} · ${getIP(req)}`, getIP(req));
    require('../services/teamAlerts').security(`${admin.email} signed in to the admin portal from a new device: ${label} (${getIP(req)}).`);
  }
}

// ── Step 1: email + password ────────────────────────────────
router.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ success: false, error: 'Email and password required.' });
  const keys = lockKeys(req, email);
  const wait = auth.lockedFor(keys);
  if (wait) return res.status(429).json({ success: false, locked: true, error: lockMsg(wait) });
  try {
    const admin = await adb.getAdminFull(email);
    if (!admin || !auth.verifyPassword(password, admin.password)) {
      auth.recordFail(keys);
      await log(String(email).slice(0, 120), 'unknown', 'LOGIN_FAILED', 'Wrong email or password', getIP(req));
      const w = auth.lockedFor(keys), left = auth.triesLeft(keys);
      if (w && auth.triesLeft(keys) === 0 && admin) require('../services/teamAlerts').security(`Admin sign-in locked for 15 minutes after 5 wrong passwords: ${admin.email} from ${getIP(req)}.`);
      return res.status(w ? 429 : 401).json({ success: false, locked: !!w,
        error: w ? lockMsg(w) : `Wrong email or password. ${left} ${left === 1 ? 'try' : 'tries'} left.` });
    }
    if (!admin.is_active) return res.status(403).json({ success: false, error: 'This account has been deactivated.' });
    if (admin.role !== 'superadmin' && admin.org_id && admin.org_status !== 'active') return res.status(403).json({ success: false, error: 'Your organization\'s access is paused. Contact Genjutsu.' });
    if (!auth.isHashed(admin.password)) await adb.setAdminPassword(admin.admin_id, auth.hashPassword(password));
    if (admin.totp_enabled) {
      req.session.pendingAdmin = { id: admin.admin_id, at: Date.now() };
      return res.json({ success: true, needs2fa: true });
    }
    await finishLogin(req, admin);
    res.json({ success: true, admin: req.session.admin, suggest2fa: true });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── Step 2: the 6-digit code, or a recovery code ────────────
router.post('/login/2fa', async (req, res) => {
  const p = req.session.pendingAdmin;
  if (!p || Date.now() - p.at > 5 * 60 * 1000) {
    delete req.session.pendingAdmin;
    return res.status(401).json({ success: false, restart: true, error: 'That took too long. Enter your password again.' });
  }
  try {
    const admin = await adb.getAdminById(p.id);
    if (!admin || !admin.is_active) return res.status(401).json({ success: false, restart: true, error: 'Sign in again.' });
    const keys = lockKeys(req, admin.email);
    const wait = auth.lockedFor(keys);
    if (wait) return res.status(429).json({ success: false, locked: true, error: lockMsg(wait) });
    const { code, recovery } = req.body || {};
    let ok = false;
    if (recovery) {
      const list = JSON.parse(admin.recovery_codes || '[]');
      const h = auth.sha256(String(recovery).trim().toLowerCase());
      if (list.includes(h)) { ok = true; await adb.setRecoveryCodes(admin.admin_id, list.filter(x => x !== h)); }
    } else {
      const step = auth.verifyTotp(open(admin.totp_secret), code);
      if (step > Number(admin.totp_last_step || 0)) { ok = true; await adb.setTotpStep(admin.admin_id, step); }   // each code works once
    }
    if (!ok) {
      auth.recordFail(keys);
      await log(admin.email, admin.role, 'LOGIN_FAILED', 'Wrong 2-step code', getIP(req));
      const w = auth.lockedFor(keys);
      return res.status(w ? 429 : 401).json({ success: false, locked: !!w, error: w ? lockMsg(w) : 'That code is wrong or already used.' });
    }
    await finishLogin(req, admin);
    if (recovery) await log(admin.email, admin.role, 'RECOVERY_CODE_USED', 'Signed in with a recovery code', getIP(req));
    res.json({ success: true, admin: req.session.admin });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.post('/logout', async (req, res) => {
  if (req.session?.admin?.loggedIn) await log(req.session.admin.email, req.session.admin.role, 'LOGOUT', 'Admin logged out', getIP(req));
  req.session.admin = null;
  res.json({ success: true });
});

router.get('/me', (req, res) => {
  const a = req.session?.admin;
  if (a?.loggedIn && (!a.lastSeen || Date.now() - a.lastSeen <= IDLE_MS)) return res.json({ loggedIn: true, admin: a });
  if (a) req.session.admin = null;
  res.json({ loggedIn: false });
});

// ── Your own account ────────────────────────────────────────
router.get('/me/security', requireAdmin, async (req, res) => {
  try {
    const admin = await adb.getAdminById(req.session.admin.adminId);
    res.json({ success: true, twoFactor: !!admin?.totp_enabled,
      recoveryLeft: JSON.parse(admin?.recovery_codes || '[]').length,
      passwordChangedAt: admin?.password_changed_at,
      devices: await adb.listDevices(req.session.admin.email),
      readOnly: !!req.session.admin.readOnly });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.post('/me/password', requireAdmin, async (req, res) => {
  const { current, next } = req.body || {};
  try {
    const admin = await adb.getAdminById(req.session.admin.adminId);
    if (!admin || !auth.verifyPassword(current, admin.password)) return res.status(400).json({ success: false, error: 'Your current password is wrong.' });
    const problem = auth.passwordProblem(next);
    if (problem) return res.status(400).json({ success: false, error: problem });
    if (current === next) return res.status(400).json({ success: false, error: 'Choose a new password, not the same one.' });
    await adb.setAdminPassword(admin.admin_id, auth.hashPassword(next));
    await log(admin.email, admin.role, 'PASSWORD_CHANGED', 'Changed own password', getIP(req));
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.post('/me/2fa/setup', requireAdmin, async (req, res) => {
  try {
    const admin = await adb.getAdminById(req.session.admin.adminId);
    if (admin.totp_enabled) return res.status(400).json({ success: false, error: '2-step login is already on.' });
    const secret = auth.newTotpSecret();
    req.session.totpSetup = { secret: seal(secret), at: Date.now() };
    res.json({ success: true, secret, qr: await QRCode.toDataURL(auth.otpauthUrl(secret, admin.email), { margin: 1, width: 220 }) });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.post('/me/2fa/enable', requireAdmin, async (req, res) => {
  const pending = req.session.totpSetup;
  if (!pending || Date.now() - pending.at > 15 * 60 * 1000) return res.status(400).json({ success: false, error: 'Start the setup again.' });
  try {
    const secret = open(pending.secret);
    const step = auth.verifyTotp(secret, req.body?.code);
    if (step < 0) return res.status(400).json({ success: false, error: 'That code is wrong. Check the time on your phone and try again.' });
    const codes = auth.recoveryCodes();
    await adb.setAdminTotp(req.session.admin.adminId, { secret: seal(secret), enabled: true, recovery: codes.map(c => auth.sha256(c)) });
    await adb.setTotpStep(req.session.admin.adminId, step);
    delete req.session.totpSetup;
    req.session.admin.twoFactor = true;
    await log(req.session.admin.email, req.session.admin.role, '2FA_ENABLED', 'Turned on 2-step login', getIP(req));
    res.json({ success: true, recoveryCodes: codes });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.post('/me/2fa/disable', requireAdmin, async (req, res) => {
  try {
    const admin = await adb.getAdminById(req.session.admin.adminId);
    if (!auth.verifyPassword(req.body?.password, admin.password)) return res.status(400).json({ success: false, error: 'Your password is wrong.' });
    if (auth.verifyTotp(open(admin.totp_secret), req.body?.code) < 0) return res.status(400).json({ success: false, error: 'That code is wrong.' });
    await adb.setAdminTotp(admin.admin_id, { secret: null, enabled: false, recovery: null });
    req.session.admin.twoFactor = false;
    await log(admin.email, admin.role, '2FA_DISABLED', 'Turned off 2-step login', getIP(req));
    require('../services/teamAlerts').security(`${admin.email} turned off 2-step login.`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.post('/me/readonly', requireAdmin, async (req, res) => {
  req.session.admin.readOnly = !!req.body?.on;
  await log(req.session.admin.email, req.session.admin.role, 'READ_ONLY', req.session.admin.readOnly ? 'Read-only mode on' : 'Read-only mode off', getIP(req));
  res.json({ success: true, readOnly: req.session.admin.readOnly });
});

module.exports = router;
