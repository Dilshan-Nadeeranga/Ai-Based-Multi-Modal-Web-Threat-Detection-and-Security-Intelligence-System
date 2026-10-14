// Rate limiting of /api/auth/login and /api/auth/register (own process, so limits can be lowered).
process.env.NODE_ENV = "test";
process.env.LOGIN_RATE_LIMIT_MAX = "3";
process.env.REGISTER_RATE_LIMIT_MAX = "2";
require("dotenv").config({ quiet: true });

const { after, before, test } = require("node:test");
const assert = require("node:assert/strict");

const app = require("../src/app");
const { closePool } = require("../src/config/database");

let server;
let baseUrl;

before(async () => {
  server = app.listen(0);
  await new Promise((resolve) => server.once("listening", resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  await closePool();
});

function post(path, body) {
  return fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

test("login is limited per client after the configured number of attempts", async () => {
  const statuses = [];
  for (let i = 0; i < 4; i += 1) {
    statuses.push((await post("/api/auth/login", { email: "nobody@ratelimit.scamtrace.local", password: "WrongPass1!" })).status);
  }
  assert.deepEqual(statuses, [401, 401, 401, 429]);
});

test("registration is limited separately", async () => {
  const statuses = [];
  for (let i = 0; i < 3; i += 1) {
    statuses.push((await post("/api/auth/register", { name: "x", email: "bad", password: "short" })).status);
  }
  assert.deepEqual(statuses, [400, 400, 429]);
  const body = await (await post("/api/auth/register", {})).json();
  assert.match(body.message, /Too many registration attempts/);
});
