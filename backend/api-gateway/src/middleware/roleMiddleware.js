const AppError = require("../utils/AppError");

/** Allow the request only for the given roles. Must run after requireAuth (401 vs 403). */
function requireRole(...roles) {
  return function roleGuard(req, res, next) {
    if (!req.user) throw new AppError(401, "Authentication required. Please log in.");
    if (!roles.includes(req.user.role)) {
      throw new AppError(403, "You do not have permission to perform this action.");
    }
    next();
  };
}

module.exports = { requireRole };
