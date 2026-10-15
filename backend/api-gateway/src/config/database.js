const { Pool } = require("pg");

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL is not set. Copy .env.example to .env and configure PostgreSQL.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: Number(process.env.DB_POOL_MAX) || 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

pool.on("error", (error) => {
  // Idle-client errors must not crash the gateway; never log connection strings.
  console.error("PostgreSQL pool error:", error.code || error.message);
});

/** Parameterized query helper — always pass user input through `params`. */
function query(text, params = []) {
  return pool.query(text, params);
}

async function ping() {
  try {
    await pool.query("SELECT 1");
    return true;
  } catch {
    return false;
  }
}

function closePool() {
  return pool.end();
}

module.exports = { pool, query, ping, closePool };
