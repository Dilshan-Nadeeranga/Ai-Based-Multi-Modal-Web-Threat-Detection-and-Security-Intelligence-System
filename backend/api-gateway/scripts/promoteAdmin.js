// Promote an existing, registered account to ADMIN (bootstrap for the first administrator).
// Usage: npm run promote-admin -- someone@example.com
// The account registers normally first, so this script never handles a password.
require("dotenv").config({ quiet: true });

const { closePool, query } = require("../src/config/database");
const { validateEmail } = require("../src/utils/validation");

async function main() {
  const { value: email, error } = validateEmail(process.argv[2]);
  if (error) {
    console.error("Usage: npm run promote-admin -- <registered-email>");
    process.exitCode = 1;
    return;
  }
  const { rows } = await query(
    "UPDATE users SET role = 'ADMIN', is_active = TRUE WHERE email = $1 RETURNING id, name, email, role",
    [email]
  );
  if (!rows[0]) {
    console.error(`No registered user with email ${email}. Register the account first.`);
    process.exitCode = 1;
    return;
  }
  console.log(`Promoted ${rows[0].email} (${rows[0].id}) to ADMIN.`);
}

main()
  .catch((err) => {
    console.error("Promotion failed:", err.message);
    process.exitCode = 1;
  })
  .finally(() => closePool());
