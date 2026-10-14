const bcrypt = require("bcryptjs");
const { query } = require("../config/database");
const AppError = require("../utils/AppError");
const { clearAuthCookie, setAuthCookie } = require("../utils/generateToken");
const { SAFE_USER_COLUMNS, toSafeUser } = require("../utils/userSql");
const {
  assertValid,
  normalizeEmail,
  validateEmail,
  validateName,
  validatePassword,
} = require("../utils/validation");

const BCRYPT_ROUNDS = 12;
const INVALID_CREDENTIALS = "Invalid email or password";
// Compared against when the email is unknown so response time does not reveal which emails exist.
const DUMMY_HASH = bcrypt.hashSync("scamtrace-timing-equalizer", BCRYPT_ROUNDS);

/** POST /api/auth/register — every self-registration becomes a USER. */
async function register(req, res) {
  const { name, email, password } = assertValid({
    name: validateName(req.body?.name),
    email: validateEmail(req.body?.email),
    password: validatePassword(req.body?.password),
  });

  const existing = await query("SELECT 1 FROM users WHERE email = $1", [email]);
  if (existing.rowCount) throw new AppError(409, "An account with this email already exists.");

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  let rows;
  try {
    ({ rows } = await query(
      `INSERT INTO users (name, email, password_hash, role)
       VALUES ($1, $2, $3, 'USER')
       RETURNING ${SAFE_USER_COLUMNS}`,
      [name, email, passwordHash]
    ));
  } catch (error) {
    if (error.code === "23505") throw new AppError(409, "An account with this email already exists.");
    throw error;
  }

  res.status(201).json({ message: "Registration successful", user: toSafeUser(rows[0]) });
}

/** POST /api/auth/login — generic error for unknown email and wrong password. */
async function login(req, res) {
  const email = normalizeEmail(req.body?.email);
  const password = typeof req.body?.password === "string" ? req.body.password : "";
  if (!email || !password) throw new AppError(400, "Email and password are required.");

  const { rows } = await query(
    `SELECT ${SAFE_USER_COLUMNS}, password_hash FROM users WHERE email = $1`,
    [email]
  );
  const user = rows[0];
  const passwordMatches = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);
  if (!user || !passwordMatches) throw new AppError(401, INVALID_CREDENTIALS);
  if (!user.is_active) throw new AppError(403, "This account has been disabled. Contact an administrator.");

  setAuthCookie(res, user.id);
  res.json({ message: "Login successful", user: toSafeUser(user) });
}

/** POST /api/auth/logout */
function logout(req, res) {
  clearAuthCookie(res);
  res.json({ message: "Logout successful" });
}

/** GET /api/auth/me — req.user was loaded fresh from PostgreSQL by requireAuth. */
function me(req, res) {
  res.json({ user: req.user });
}

module.exports = { register, login, logout, me };
