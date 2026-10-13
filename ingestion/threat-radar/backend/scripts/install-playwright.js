/**
 * Download Playwright Chromium into backend/.playwright-browsers.
 * Run via: npm run playwright:install  (or automatically on npm start)
 */
import { createRequire } from "module";
import { execSync } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { backendRootFrom } from "../paths.js";

const backendRoot = backendRootFrom(import.meta.url);
const require = createRequire(import.meta.url);
const required = process.argv.includes("--required");

await import("../playwright-env.js");

function findPlaywrightCli() {
  const direct = path.join(backendRoot, "node_modules", "playwright", "cli.js");
  if (fs.existsSync(direct)) return direct;

  try {
    const pkgJson = require.resolve("playwright/package.json");
    const cli = path.join(path.dirname(pkgJson), "cli.js");
    if (fs.existsSync(cli)) return cli;
  } catch {
    /* package not installed */
  }
  return null;
}

function ensurePlaywrightPackage() {
  let cli = findPlaywrightCli();
  if (cli) return cli;

  if (!required) {
    console.log("[playwright] Skipping — playwright not installed yet");
    process.exit(0);
  }

  console.log("[playwright] playwright npm package missing — installing…");
  execSync("npm install playwright@1.48.2 --no-audit --no-fund", {
    cwd: backendRoot,
    stdio: "inherit",
    env: { ...process.env },
  });

  cli = findPlaywrightCli();
  if (!cli) {
    console.error("[playwright] playwright package still missing after npm install");
    process.exit(1);
  }
  return cli;
}

const playwrightCli = ensurePlaywrightPackage();

function listBrowserDir() {
  const dir = process.env.PLAYWRIGHT_BROWSERS_PATH;
  if (!dir || !fs.existsSync(dir)) {
    console.log(`[playwright] Browsers dir missing: ${dir}`);
    return;
  }
  console.log(`[playwright] Contents of ${dir}:`);
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    console.log(`  ${entry.isDirectory() ? "d" : "f"} ${entry.name}`);
  }
}

function runInstall(extraArgs) {
  const cmd = `node "${playwrightCli}" install ${extraArgs}`.trim();
  console.log(`[playwright] ${cmd}`);
  execSync(cmd, {
    stdio: "inherit",
    env: { ...process.env },
    cwd: backendRoot,
    timeout: 600_000,
  });
}

async function verifyBinary() {
  const { chromium } = await import("playwright");
  const exe = chromium.executablePath();
  const ok = Boolean(exe && fs.existsSync(exe));
  console.log(`[playwright] Browsers dir: ${process.env.PLAYWRIGHT_BROWSERS_PATH}`);
  console.log(`[playwright] Executable: ${exe}`);
  console.log(`[playwright] Exists: ${ok}`);
  if (!ok) listBrowserDir();
  return ok;
}

if (await verifyBinary()) {
  console.log("[playwright] Already installed — skipping download");
  process.exit(0);
}

console.log("[playwright] Downloading Chromium…");

const installPlans =
  process.platform === "linux"
    ? ["chromium", "--with-deps chromium"]
    : ["chromium"];

let installed = false;
for (const args of installPlans) {
  try {
    runInstall(args);
    if (await verifyBinary()) {
      installed = true;
      break;
    }
    console.warn(`[playwright] Binary still missing after: ${args}`);
  } catch (err) {
    console.warn(`[playwright] Install failed (${args}):`, err.message);
  }
}

if (!installed) {
  listBrowserDir();
  console.error("[playwright] Chromium could not be installed");
  process.exit(required ? 1 : 0);
}

console.log("[playwright] Chromium install complete");
