/** Column list that never includes password_hash — use it for every query whose rows reach a response. */
const SAFE_USER_COLUMNS = "id, name, email, role, is_active, created_at, updated_at";

/** Public representation of a user row (no password hash, ever). */
function toSafeUser(row, { includeStatus = false } = {}) {
  const user = { id: row.id, name: row.name, email: row.email, role: row.role };
  if (includeStatus) {
    user.is_active = row.is_active;
    user.created_at = row.created_at;
    user.updated_at = row.updated_at;
  }
  return user;
}

module.exports = { SAFE_USER_COLUMNS, toSafeUser };
