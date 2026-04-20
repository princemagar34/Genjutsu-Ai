// ============================================================
// middleware/authMiddleware.js
// ============================================================

function requireAuth(req, res, next) {
  // Check cookie session first
  if (req.session && req.session.user) return next();

  // Check x-session-id header (for cross-domain requests)
  const sid = req.headers['x-session-id'];
  if (sid && req.sessionStore) {
    req.sessionStore.get(sid, (err, sessionData) => {
      if (!err && sessionData && sessionData.user) {
        req.session.user = sessionData.user;
        return next();
      }
      return res.status(401).json({ success: false, error: 'Unauthorized. Please log in.' });
    });
    return;
  }

  return res.status(401).json({ success: false, error: 'Unauthorized. Please log in.' });
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.admin) return next();
  return res.status(403).json({ success: false, error: 'Admin access required.' });
}

module.exports = { requireAuth, requireAdmin };
