const ADMIN_ROLES = new Set(['admin', 'superadmin']);

// Must run after authMiddleware. Authorization is always decided from the database
// user loaded by authMiddleware, never from anything the client sends.
const requireAdmin = (req, res, next) => {
  if (!req.user || !ADMIN_ROLES.has(req.user.role)) {
    return res.status(403).json({
      success: false,
      code: 'ADMIN_REQUIRED',
      message: 'Administrator access is required.',
    });
  }
  return next();
};

const requireSuperadmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'superadmin') {
    return res.status(403).json({
      success: false,
      code: 'SUPERADMIN_REQUIRED',
      message: 'This action requires a super administrator.',
    });
  }
  return next();
};

module.exports = { requireAdmin, requireSuperadmin };
