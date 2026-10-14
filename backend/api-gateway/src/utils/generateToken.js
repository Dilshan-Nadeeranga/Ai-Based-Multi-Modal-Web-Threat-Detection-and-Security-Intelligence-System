const jwt = require("jsonwebtoken");
const { isProduction, jwtExpiresIn, jwtSecret } = require("../config/env");

const AUTH_COOKIE = "scamtrace_token";
const JWT_ALGORITHM = "HS256";
const ONE_HOUR_MS = 60 * 60 * 1000;

/** Cookie flags shared by set and clear (browsers only clear a cookie with matching flags). */
function cookieOptions() {
  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? "none" : "lax",
    path: "/",
  };
}

/** The token carries only the user id; role and status are re-read from PostgreSQL on every request. */
function generateToken(userId) {
  return jwt.sign({ sub: userId }, jwtSecret, { algorithm: JWT_ALGORITHM, expiresIn: jwtExpiresIn });
}

function verifyToken(token) {
  return jwt.verify(token, jwtSecret, { algorithms: [JWT_ALGORITHM] });
}

function setAuthCookie(res, userId) {
  res.cookie(AUTH_COOKIE, generateToken(userId), { ...cookieOptions(), maxAge: ONE_HOUR_MS });
}

function clearAuthCookie(res) {
  res.clearCookie(AUTH_COOKIE, cookieOptions());
}

module.exports = {
  AUTH_COOKIE,
  generateToken,
  verifyToken,
  setAuthCookie,
  clearAuthCookie,
  cookieOptions,
};
