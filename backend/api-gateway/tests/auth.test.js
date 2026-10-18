// Integration tests for gateway authentication / authorization.
// Runs against the PostgreSQL database in .env; every test account uses TEST_DOMAIN and is deleted afterwards.
process.env.NODE_ENV = "test";
process.env.LOGIN_RATE_LIMIT_MAX = "1000";
process.env.REGISTER_RATE_LIMIT_MAX = "1000";
for (const key of ["C1_URL", "C2_URL", "C3_URL"]) process.env[key] = "";
process.env.C4_URL = "http://127.0.0.1:9"; // closed port: C4 calls fail fast and are reported as unavailable
require("dotenv").config({ quiet: true });

const { after, before, describe, test } = require("node:test");
const assert = require("node:assert/strict");
const jwt = require("jsonwebtoken");

const app = require("../src/app");
const { closePool, query } = require("../src/config/database");

const TEST_DOMAIN = "auth-test.scamtrace.local";
const PASSWORD = "StrongPassword123!";
let server;
let baseUrl;

function email(name) {
  return `${name}@${TEST_DOMAIN}`;
}

async function cleanup() {
  const owned = "SELECT id FROM users WHERE email LIKE $1";
  await query(`DELETE FROM analysis_records WHERE user_id IN (${owned})`, [`%@${TEST_DOMAIN}`]);
  await query(`DELETE FROM code_audit_scans WHERE user_id IN (${owned})`, [`%@${TEST_DOMAIN}`]);
  await query("DELETE FROM users WHERE email LIKE $1", [`%@${TEST_DOMAIN}`]);
}

async function request(method, path, { body, cookie } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (cookie) headers.Cookie = cookie;
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  return {
    status: response.status,
    text,
    body: text ? JSON.parse(text) : null,
    setCookie: response.headers.getSetCookie(),
  };
}

function tokenCookie(setCookie) {
  const header = setCookie.find((value) => value.startsWith("scamtrace_token="));
  return header ? header.split(";")[0] : null;
}

async function registerAndLogin(name, role = "USER") {
  await request("POST", "/api/auth/register", { body: { name: `Test ${name}`, email: email(name), password: PASSWORD } });
  if (role === "ADMIN") await query("UPDATE users SET role = 'ADMIN' WHERE email = $1", [email(name)]);
  const login = await request("POST", "/api/auth/login", { body: { email: email(name), password: PASSWORD } });
  return { cookie: tokenCookie(login.setCookie), user: login.body.user };
}

before(async () => {
  await cleanup();
  server = app.listen(0);
  await new Promise((resolve) => server.once("listening", resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await cleanup();
  await new Promise((resolve) => server.close(resolve));
  await closePool();
});

describe("registration", () => {
  test("1. successful registration creates a USER and returns safe data", async () => {
    const res = await request("POST", "/api/auth/register", {
      body: { name: "  Thamidu   Peiris ", email: " Reg.User@Auth-Test.ScamTrace.local ", password: PASSWORD, role: "ADMIN" },
    });
    assert.equal(res.status, 201);
    assert.deepEqual(Object.keys(res.body.user).sort(), ["email", "id", "name", "role"]);
    assert.equal(res.body.user.role, "USER"); // a submitted role is ignored
    assert.equal(res.body.user.email, email("reg.user"));
    assert.equal(res.body.user.name, "Thamidu Peiris");
    assert.doesNotMatch(res.text, /password/i);

    const { rows } = await query("SELECT role, password_hash FROM users WHERE email = $1", [email("reg.user")]);
    assert.equal(rows[0].role, "USER");
    assert.match(rows[0].password_hash, /^\$2[aby]\$12\$/); // bcrypt, never plaintext
    assert.notEqual(rows[0].password_hash, PASSWORD);
  });

  test("2. duplicate email (any case) is rejected with 409", async () => {
    const res = await request("POST", "/api/auth/register", {
      body: { name: "Again", email: "REG.USER@auth-test.scamtrace.local", password: PASSWORD },
    });
    assert.equal(res.status, 409);
  });

  test("3. weak or invalid registration data is rejected with 400", async () => {
    const cases = [
      { name: "A", email: email("short-name"), password: PASSWORD },
      { name: "Valid Name", email: "not-an-email", password: PASSWORD },
      { name: "Valid Name", email: email("weak"), password: "short" },
      { name: "Valid Name", email: email("long"), password: "x".repeat(73) },
      {},
    ];
    for (const body of cases) {
      const res = await request("POST", "/api/auth/register", { body });
      assert.equal(res.status, 400, JSON.stringify(body));
      assert.ok(res.body.message);
    }
  });
});

describe("login / session", () => {
  test("4. successful login sets an HttpOnly cookie and returns the user", async () => {
    const res = await request("POST", "/api/auth/login", { body: { email: email("reg.user"), password: PASSWORD } });
    assert.equal(res.status, 200);
    assert.equal(res.body.message, "Login successful");
    assert.equal(res.body.user.role, "USER");
    assert.doesNotMatch(res.text, /password|token/i);
    const header = res.setCookie.find((value) => value.startsWith("scamtrace_token="));
    assert.match(header, /HttpOnly/i);
    assert.match(header, /SameSite=Lax/i);
    assert.match(header, /Max-Age=3600/);
    assert.equal(jwt.decode(tokenCookie(res.setCookie).split("=")[1]).exp - jwt.decode(tokenCookie(res.setCookie).split("=")[1]).iat, 3600);
  });

  test("5/6. wrong password and unknown email give the same generic error", async () => {
    const wrong = await request("POST", "/api/auth/login", { body: { email: email("reg.user"), password: "WrongPassword1!" } });
    const unknown = await request("POST", "/api/auth/login", { body: { email: email("nobody"), password: PASSWORD } });
    for (const res of [wrong, unknown]) {
      assert.equal(res.status, 401);
      assert.deepEqual(res.body, { message: "Invalid email or password" });
      assert.equal(tokenCookie(res.setCookie), null);
    }
  });

  test("7. disabled accounts cannot log in, and existing sessions stop working", async () => {
    const { cookie } = await registerAndLogin("disabled");
    await query("UPDATE users SET is_active = FALSE WHERE email = $1", [email("disabled")]);
    const login = await request("POST", "/api/auth/login", { body: { email: email("disabled"), password: PASSWORD } });
    assert.equal(login.status, 403);
    assert.equal(tokenCookie(login.setCookie), null);
    assert.equal((await request("GET", "/api/auth/me", { cookie })).status, 401);
  });

  test("8. GET /auth/me returns the current user when logged in", async () => {
    const { cookie, user } = await registerAndLogin("me");
    const res = await request("GET", "/api/auth/me", { cookie });
    assert.equal(res.status, 200);
    assert.deepEqual(res.body, { user });
  });

  test("9. GET /auth/me without a cookie is 401", async () => {
    const res = await request("GET", "/api/auth/me");
    assert.equal(res.status, 401);
  });

  test("10. logout clears the cookie", async () => {
    const res = await request("POST", "/api/auth/logout");
    assert.equal(res.status, 200);
    const header = res.setCookie.find((value) => value.startsWith("scamtrace_token="));
    assert.match(header, /scamtrace_token=;/);
    assert.match(header, /Expires=Thu, 01 Jan 1970/);
  });

  test("13. expired, forged and malformed tokens are rejected", async () => {
    const { user } = await registerAndLogin("tokens");
    const expired = jwt.sign({ sub: user.id }, process.env.JWT_SECRET, { algorithm: "HS256", expiresIn: -10 });
    const forged = jwt.sign({ sub: user.id }, "x".repeat(48), { algorithm: "HS256", expiresIn: "1h" });
    const unsigned = jwt.sign({ sub: user.id }, null, { algorithm: "none" });
    for (const token of [expired, forged, unsigned, "garbage"]) {
      const res = await request("GET", "/api/auth/me", { cookie: `scamtrace_token=${token}` });
      assert.equal(res.status, 401);
    }
    const res = await request("GET", "/api/auth/me", { cookie: `scamtrace_token=${expired}` });
    assert.match(res.body.message, /expired/i);
  });
});

describe("roles and profile", () => {
  test("11. USER calling an ADMIN route gets 403; anonymous gets 401", async () => {
    const { cookie } = await registerAndLogin("plain");
    assert.equal((await request("GET", "/api/admin/users", { cookie })).status, 403);
    assert.equal((await request("GET", "/api/admin/users")).status, 401);
  });

  test("12. ADMIN can list users, and no password hash is returned", async () => {
    const { cookie } = await registerAndLogin("boss", "ADMIN");
    const res = await request("GET", "/api/admin/users", { cookie });
    assert.equal(res.status, 200);
    assert.ok(res.body.users.some((u) => u.email === email("boss") && u.role === "ADMIN"));
    assert.doesNotMatch(res.text, /password/i);
  });

  test("role changes take effect immediately (role is read from the DB, not the JWT)", async () => {
    const { cookie } = await registerAndLogin("promoted");
    assert.equal((await request("GET", "/api/admin/users", { cookie })).status, 403);
    await query("UPDATE users SET role = 'ADMIN' WHERE email = $1", [email("promoted")]);
    assert.equal((await request("GET", "/api/admin/users", { cookie })).status, 200);
  });

  test("14. users cannot update their own role or status", async () => {
    const { cookie } = await registerAndLogin("selfrole");
    for (const body of [{ role: "ADMIN" }, { is_active: false }, { name: "Ok Name", role: "ADMIN" }]) {
      const res = await request("PATCH", "/api/users/profile", { cookie, body });
      assert.equal(res.status, 400);
    }
    const { rows } = await query("SELECT role, is_active FROM users WHERE email = $1", [email("selfrole")]);
    assert.deepEqual(rows[0], { role: "USER", is_active: true });
  });

  test("profile update changes name/email and rejects a taken email", async () => {
    const { cookie } = await registerAndLogin("profile");
    const ok = await request("PATCH", "/api/users/profile", {
      cookie, body: { name: "New Name", email: "Profile.Two@auth-test.scamtrace.local" },
    });
    assert.equal(ok.status, 200);
    assert.equal(ok.body.user.email, email("profile.two"));
    assert.ok(ok.body.user.created_at);
    const taken = await request("PATCH", "/api/users/profile", { cookie, body: { email: email("reg.user") } });
    assert.equal(taken.status, 409);
    const profile = await request("GET", "/api/users/profile", { cookie });
    assert.equal(profile.body.user.name, "New Name");
    assert.doesNotMatch(profile.text, /password/i);
  });

  test("password change requires the current password", async () => {
    const { cookie } = await registerAndLogin("pwchange");
    const wrong = await request("PATCH", "/api/users/password", {
      cookie, body: { currentPassword: "nope-nope", newPassword: "AnotherPass456!" },
    });
    assert.equal(wrong.status, 400);
    const ok = await request("PATCH", "/api/users/password", {
      cookie, body: { currentPassword: PASSWORD, newPassword: "AnotherPass456!" },
    });
    assert.equal(ok.status, 200);
    const login = await request("POST", "/api/auth/login", { body: { email: email("pwchange"), password: "AnotherPass456!" } });
    assert.equal(login.status, 200);
  });
});

describe("admin user management", () => {
  test("admin can deactivate/activate users and change roles; invalid roles rejected", async () => {
    const { cookie } = await registerAndLogin("manager", "ADMIN");
    const { user: target } = await registerAndLogin("target");

    const off = await request("PATCH", `/api/admin/users/${target.id}/status`, { cookie, body: { is_active: false } });
    assert.equal(off.status, 200);
    assert.equal(off.body.user.is_active, false);
    const on = await request("PATCH", `/api/admin/users/${target.id}/status`, { cookie, body: { is_active: true } });
    assert.equal(on.body.user.is_active, true);

    const promote = await request("PATCH", `/api/admin/users/${target.id}/role`, { cookie, body: { role: "ADMIN" } });
    assert.equal(promote.body.user.role, "ADMIN");
    const demote = await request("PATCH", `/api/admin/users/${target.id}/role`, { cookie, body: { role: "USER" } });
    assert.equal(demote.body.user.role, "USER");

    for (const role of ["ANALYST", "admin", "", null]) {
      const res = await request("PATCH", `/api/admin/users/${target.id}/role`, { cookie, body: { role } });
      assert.equal(res.status, 400);
    }
    const bad = await request("PATCH", `/api/admin/users/${target.id}/status`, { cookie, body: { is_active: "no" } });
    assert.equal(bad.status, 400);
    assert.equal((await request("GET", "/api/admin/users/not-a-uuid", { cookie })).status, 400);
    assert.equal((await request("GET", "/api/admin/users/00000000-0000-4000-8000-000000000000", { cookie })).status, 404);
    const single = await request("GET", `/api/admin/users/${target.id}`, { cookie });
    assert.equal(single.body.user.email, email("target"));
    assert.doesNotMatch(single.text, /password/i);
  });

  test("admin cannot deactivate or demote their own account", async () => {
    const { cookie, user } = await registerAndLogin("selfadmin", "ADMIN");
    const status = await request("PATCH", `/api/admin/users/${user.id}/status`, { cookie, body: { is_active: false } });
    const role = await request("PATCH", `/api/admin/users/${user.id}/role`, { cookie, body: { role: "USER" } });
    assert.equal(status.status, 400);
    assert.equal(role.status, 400);
  });
});

describe("ScamTrace ownership", () => {
  test("analysis requires auth; USER sees only own history; ADMIN may see all", async () => {
    assert.equal((await request("POST", "/api/analysis", { body: { url: "https://example.com" } })).status, 401);
    assert.equal((await request("POST", "/api/analyze", { body: { url: "https://example.com" } })).status, 401);

    const alice = await registerAndLogin("alice");
    const bob = await registerAndLogin("bob");
    const admin = await registerAndLogin("auditor", "ADMIN");

    const created = await request("POST", "/api/analysis", { cookie: alice.cookie, body: { url: "https://example.com" } });
    assert.equal(created.status, 201);
    const id = created.body.analysis_id;

    const aliceHistory = await request("GET", "/api/analysis/history", { cookie: alice.cookie });
    assert.ok(aliceHistory.body.analyses.some((a) => a.analysis_id === id));
    const bobHistory = await request("GET", "/api/analysis/history?all=true", { cookie: bob.cookie });
    assert.equal(bobHistory.body.scope, "own");
    assert.ok(!bobHistory.body.analyses.some((a) => a.analysis_id === id));

    assert.equal((await request("GET", `/api/analysis/${id}`, { cookie: bob.cookie })).status, 404);
    assert.equal((await request("GET", `/api/analysis/${id}`, { cookie: alice.cookie })).status, 200);
    assert.equal((await request("GET", `/api/analysis/${id}`, { cookie: admin.cookie })).status, 200);
    const all = await request("GET", "/api/admin/analyses", { cookie: admin.cookie });
    assert.ok(all.body.analyses.some((a) => a.analysis_id === id));
  });

  test("code-audit scans are visible only to their owner and ADMIN", async () => {
    const owner = await registerAndLogin("scanowner");
    const other = await registerAndLogin("scanother");
    const admin = await registerAndLogin("scanadmin", "ADMIN");
    await query(
      "INSERT INTO code_audit_scans (scan_id, user_id, repository_url, status) VALUES ($1, $2, $3, 'completed')",
      ["SCAN-AUTHTEST01", owner.user.id, "https://github.com/example/repo"]
    );

    assert.equal((await request("GET", "/api/code-audit/SCAN-AUTHTEST01")).status, 401);
    assert.equal((await request("GET", "/api/code-audit/SCAN-AUTHTEST01", { cookie: other.cookie })).status, 404);
    const mine = await request("GET", "/api/code-audit/SCAN-AUTHTEST01", { cookie: owner.cookie });
    assert.equal(mine.status, 200);
    assert.equal(mine.body.scan.scan_id, "SCAN-AUTHTEST01");
    assert.equal(mine.body.c4_available, false);
    assert.equal((await request("GET", "/api/code-audit/SCAN-AUTHTEST01", { cookie: admin.cookie })).status, 200);

    const list = await request("GET", "/api/code-audit", { cookie: other.cookie });
    assert.ok(!list.body.scans.some((s) => s.scan_id === "SCAN-AUTHTEST01"));

    const submit = await request("POST", "/api/code-audit", {
      cookie: owner.cookie, body: { repository_url: "https://github.com/example/repo" },
    });
    assert.equal(submit.status, 502); // C4 unreachable in tests: controlled error, nothing recorded
    assert.equal((await request("POST", "/api/code-audit", { cookie: owner.cookie, body: {} })).status, 400);
  });

  test("code-audit projects group the owner's scans by repository", async () => {
    const owner = await registerAndLogin("projowner");
    const other = await registerAndLogin("projother");
    const insert = (scanId, url, minutesAgo) => query(
      `INSERT INTO code_audit_scans (scan_id, user_id, repository_url, status, created_at)
       VALUES ($1, $2, $3, 'completed', now() - make_interval(mins => $4))`,
      [scanId, owner.user.id, url, minutesAgo]
    );
    await insert("SCAN-PROJTEST01", "https://github.com/example/alpha", 30);
    await insert("SCAN-PROJTEST02", "https://github.com/example/alpha", 5);
    await insert("SCAN-PROJTEST03", "https://github.com/example/beta", 10);

    assert.equal((await request("GET", "/api/code-audit/projects")).status, 401);
    const mine = await request("GET", "/api/code-audit/projects", { cookie: owner.cookie });
    assert.equal(mine.status, 200);
    assert.equal(mine.body.projects.length, 2);
    const [alpha, beta] = mine.body.projects;
    assert.equal(alpha.name, "alpha");
    assert.equal(alpha.latest_scan_id, "SCAN-PROJTEST02");
    assert.deepEqual(alpha.scans.map((s) => s.scan_id), ["SCAN-PROJTEST02", "SCAN-PROJTEST01"]);
    assert.equal(beta.scans.length, 1);

    const theirs = await request("GET", "/api/code-audit/projects", { cookie: other.cookie });
    assert.equal(theirs.body.projects.length, 0);
  });

  test("code-audit project delete removes only the owner's scans for that repository", async () => {
    const owner = await registerAndLogin("delowner");
    const other = await registerAndLogin("delother");
    const insert = (scanId, userId, url) => query(
      `INSERT INTO code_audit_scans (scan_id, user_id, repository_url, status) VALUES ($1, $2, $3, 'completed')`,
      [scanId, userId, url]
    );
    await insert("SCAN-DELTEST01", owner.user.id, "https://github.com/example/gamma");
    await insert("SCAN-DELTEST02", owner.user.id, "https://github.com/Example/Gamma/");
    await insert("SCAN-DELTEST03", owner.user.id, "https://github.com/example/delta");
    await insert("SCAN-DELTEST04", other.user.id, "https://github.com/example/gamma");

    assert.equal((await request("DELETE", "/api/code-audit/projects/SCAN-DELTEST01")).status, 401);
    assert.equal(
      (await request("DELETE", "/api/code-audit/projects/SCAN-DELTEST01", { cookie: other.cookie })).status, 404
    );
    assert.equal(
      (await request("DELETE", "/api/code-audit/projects/SCAN-NOPE", { cookie: owner.cookie })).status, 404
    );

    const removed = await request("DELETE", "/api/code-audit/projects/SCAN-DELTEST01", { cookie: owner.cookie });
    assert.equal(removed.status, 200);
    assert.equal(removed.body.deleted_scans, 2);

    const mine = await request("GET", "/api/code-audit/projects", { cookie: owner.cookie });
    assert.deepEqual(mine.body.projects.map((p) => p.name), ["delta"]);
    const theirs = await request("GET", "/api/code-audit/projects", { cookie: other.cookie });
    assert.equal(theirs.body.projects.length, 1);
  });
});

describe("hardening", () => {
  test("15. no response ever contains a password hash; errors hide internals", async () => {
    const res = await request("POST", "/api/auth/login", { body: "{bad json" });
    assert.equal(res.status, 400);
    const missing = await request("GET", "/api/does-not-exist");
    assert.equal(missing.status, 404);
    const { rows } = await query("SELECT password_hash FROM users WHERE email = $1", [email("reg.user")]);
    for (const path of ["/api/auth/me", "/api/users/profile", "/api/admin/users"]) {
      const { cookie } = await registerAndLogin(`hash${path.length}`, "ADMIN");
      const body = (await request("GET", path, { cookie })).text;
      assert.ok(!body.includes(rows[0].password_hash));
      assert.doesNotMatch(body, /password_hash/);
    }
  });

  test("security headers and credentialed CORS are set", async () => {
    const response = await fetch(`${baseUrl}/api/health`, { headers: { Origin: "http://localhost:5173" } });
    assert.equal(response.headers.get("access-control-allow-origin"), "http://localhost:5173");
    assert.equal(response.headers.get("access-control-allow-credentials"), "true");
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
    assert.equal(response.headers.get("x-powered-by"), null);
    const evil = await fetch(`${baseUrl}/api/health`, { headers: { Origin: "http://evil.example" } });
    assert.equal(evil.headers.get("access-control-allow-origin"), null);
  });
});
