const { query } = require("../config/database");
const AppError = require("../utils/AppError");
const { AUTH_COOKIE, clearAuthCookie, verifyToken } = require("../utils/generateToken");
const { SAFE_USER_COLUMNS, toSafeUser } = require("../utils/userSql");
const { isUuid } = require("../utils/validation");

const NOT_AUTHENTICATED = "Authentication required. Please log in.";

/**
 * Verify the JWT from the HttpOnly cookie, then load the user from PostgreSQL so
 * role changes and deactivation take effect immediately (the token is never trusted for role).
 */
async function requireAuth(req, res, next) {
  const token = req.cookies?.[AUTH_COOKIE];
  if (!token) throw new AppError(401, NOT_AUTHENTICATED);

  let payload;
  try {
    payload = verifyToken(token);
  } catch (error) {
    clearAuthCookie(res);
    const expired = error.name === "TokenExpiredError";
    throw new AppError(401, expired ? "Session expired. Please log in again." : NOT_AUTHENTICATED);
  }
  if (!isUuid(payload.sub)) {
    clearAuthCookie(res);
    throw new AppError(401, NOT_AUTHENTICATED);
  }

  const { rows } = await query(`SELECT ${SAFE_USER_COLUMNS} FROM users WHERE id = $1`, [payload.sub]);
  const user = rows[0];
  if (!user || !user.is_active) {
    clearAuthCookie(res);
    throw new AppError(401, user ? "This account has been disabled." : NOT_AUTHENTICATED);
  }

  req.user = toSafeUser(user);
  next();
}

module.exports = { requireAuth };
