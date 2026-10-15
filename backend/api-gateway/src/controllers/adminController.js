const { query } = require("../config/database");
const AppError = require("../utils/AppError");
const { SAFE_USER_COLUMNS, toSafeUser } = require("../utils/userSql");
const { ROLES, isUuid } = require("../utils/validation");

function assertUserId(id) {
  if (!isUuid(id)) throw new AppError(400, "Invalid user id.");
}

async function findUser(id) {
  const { rows } = await query(`SELECT ${SAFE_USER_COLUMNS} FROM users WHERE id = $1`, [id]);
  if (!rows[0]) throw new AppError(404, "User not found.");
  return rows[0];
}

async function countOtherActiveAdmins(excludeId) {
  const { rows } = await query(
    "SELECT count(*)::int AS total FROM users WHERE role = 'ADMIN' AND is_active AND id <> $1",
    [excludeId]
  );
  return rows[0].total;
}

/** GET /api/admin/users */
async function getUsers(req, res) {
  const { rows } = await query(`SELECT ${SAFE_USER_COLUMNS} FROM users ORDER BY created_at DESC`);
  res.json({ users: rows.map((row) => toSafeUser(row, { includeStatus: true })) });
}

/** GET /api/admin/users/:id */
async function getUserById(req, res) {
  assertUserId(req.params.id);
  res.json({ user: toSafeUser(await findUser(req.params.id), { includeStatus: true }) });
}

/** PATCH /api/admin/users/:id/status — { "is_active": boolean } */
async function updateUserStatus(req, res) {
  assertUserId(req.params.id);
  const isActive = req.body?.is_active;
  if (typeof isActive !== "boolean") throw new AppError(400, "is_active must be true or false.");
  if (req.params.id === req.user.id && !isActive) {
    throw new AppError(400, "You cannot deactivate your own account.");
  }

  const target = await findUser(req.params.id);
  if (!isActive && target.role === "ADMIN" && target.is_active && (await countOtherActiveAdmins(target.id)) === 0) {
    throw new AppError(400, "The last active administrator cannot be deactivated.");
  }

  const { rows } = await query(
    `UPDATE users SET is_active = $1 WHERE id = $2 RETURNING ${SAFE_USER_COLUMNS}`,
    [isActive, target.id]
  );
  res.json({
    message: isActive ? "User activated" : "User deactivated",
    user: toSafeUser(rows[0], { includeStatus: true }),
  });
}

/** PATCH /api/admin/users/:id/role — { "role": "USER" | "ADMIN" } */
async function updateUserRole(req, res) {
  assertUserId(req.params.id);
  const role = req.body?.role;
  if (!ROLES.includes(role)) throw new AppError(400, `Role must be one of: ${ROLES.join(", ")}.`);
  if (req.params.id === req.user.id && role !== req.user.role) {
    throw new AppError(400, "You cannot change your own role.");
  }

  const target = await findUser(req.params.id);
  if (target.role === "ADMIN" && role === "USER" && target.is_active
      && (await countOtherActiveAdmins(target.id)) === 0) {
    throw new AppError(400, "The last active administrator cannot be demoted.");
  }

  const { rows } = await query(
    `UPDATE users SET role = $1 WHERE id = $2 RETURNING ${SAFE_USER_COLUMNS}`,
    [role, target.id]
  );
  res.json({ message: "Role updated", user: toSafeUser(rows[0], { includeStatus: true }) });
}

module.exports = { getUsers, getUserById, updateUserStatus, updateUserRole };
