const AppError = require("./AppError");

function isAdmin(user) {
  return user?.role === "ADMIN";
}

/**
 * Owners and ADMINs may read a record. Others get 404 so record ids cannot be probed.
 */
function assertCanAccess(user, record, label = "Record") {
  if (!record || (!isAdmin(user) && record.user_id !== user.id)) {
    throw new AppError(404, `${label} not found.`);
  }
}

/** ADMINs may list everything with ?all=true (or via admin routes); everyone else gets only their own records. */
function listsAll(req) {
  return isAdmin(req.user) && (req.listAll === true || req.query.all === "true");
}

/** Used by /api/admin/* list routes, after requireRole("ADMIN"). */
function listAllRecords(req, res, next) {
  req.listAll = true;
  next();
}

module.exports = { isAdmin, assertCanAccess, listsAll, listAllRecords };
