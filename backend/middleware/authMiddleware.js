// ============================================================
// middleware/authMiddleware.js
// ============================================================

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ success: false, error: 'Unauthorized. Please log in.' });
}

function requireAdmin(req, res, next) {
  if (req.session && req.session.admin) return next();
  return res.status(403).json({ success: false, error: 'Admin access required.' });
}

module.exports = { requireAuth, requireAdmin };
