const bcrypt = require("bcryptjs");
const { query } = require("../config/database");
const AppError = require("../utils/AppError");
const { SAFE_USER_COLUMNS, toSafeUser } = require("../utils/userSql");
const { assertValid, validateEmail, validateName, validatePassword } = require("../utils/validation");

const BCRYPT_ROUNDS = 12;
const EDITABLE_FIELDS = ["name", "email"];

async function loadProfile(userId) {
  const { rows } = await query(`SELECT ${SAFE_USER_COLUMNS} FROM users WHERE id = $1`, [userId]);
  if (!rows[0]) throw new AppError(404, "User not found.");
  return toSafeUser(rows[0], { includeStatus: true });
}

/** GET /api/users/profile */
async function getProfile(req, res) {
  res.json({ user: await loadProfile(req.user.id) });
}

/** PATCH /api/users/profile — only name and email; role / is_active are rejected. */
async function updateProfile(req, res) {
  const body = req.body || {};
  const forbidden = Object.keys(body).filter((key) => !EDITABLE_FIELDS.includes(key));
  if (forbidden.length) {
    throw new AppError(400, `These fields cannot be updated here: ${forbidden.join(", ")}.`);
  }

  const checks = {};
  if (body.name !== undefined) checks.name = validateName(body.name);
  if (body.email !== undefined) checks.email = validateEmail(body.email);
  if (!Object.keys(checks).length) throw new AppError(400, "Provide a name or email to update.");
  const updates = assertValid(checks);

  if (updates.email && updates.email !== req.user.email) {
    const taken = await query("SELECT 1 FROM users WHERE email = $1 AND id <> $2", [updates.email, req.user.id]);
    if (taken.rowCount) throw new AppError(409, "An account with this email already exists.");
  }

  const { rows } = await query(
    `UPDATE users
        SET name = COALESCE($1, name), email = COALESCE($2, email)
      WHERE id = $3
      RETURNING ${SAFE_USER_COLUMNS}`,
    [updates.name ?? null, updates.email ?? null, req.user.id]
  );
  res.json({ message: "Profile updated", user: toSafeUser(rows[0], { includeStatus: true }) });
}

/** PATCH /api/users/password — the current password must be verified first. */
async function changePassword(req, res) {
  const currentPassword = typeof req.body?.currentPassword === "string" ? req.body.currentPassword : "";
  if (!currentPassword) throw new AppError(400, "Current password is required.");
  const { newPassword } = assertValid({ newPassword: validatePassword(req.body?.newPassword, "New password") });

  const { rows } = await query("SELECT password_hash FROM users WHERE id = $1", [req.user.id]);
  if (!rows[0] || !(await bcrypt.compare(currentPassword, rows[0].password_hash))) {
    throw new AppError(400, "Current password is incorrect.");
  }
  if (await bcrypt.compare(newPassword, rows[0].password_hash)) {
    throw new AppError(400, "New password must be different from the current password.");
  }

  const passwordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  await query("UPDATE users SET password_hash = $1 WHERE id = $2", [passwordHash, req.user.id]);
  res.json({ message: "Password updated" });
}

module.exports = { getProfile, updateProfile, changePassword };
