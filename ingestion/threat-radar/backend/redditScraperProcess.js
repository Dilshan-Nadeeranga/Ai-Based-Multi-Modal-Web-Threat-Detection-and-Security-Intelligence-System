/**
 * Manages the Reddit scraper child process.
 * - With saved browser session → Node + Playwright (full page scrape)
 * - Without session → Python RSS fallback
 * Auto-scrape on/off is controlled via website → backend/data/reddit_settings.json
 */

import { exec, spawn } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { hasSession, restoreSessionFromEnv } from "./redditAuth/session.js";
import { chromiumInstalled } from "./redditAuth/chromiumLaunch.js";
import { isAutoScrapeEnabled } from "./redditAuth/settings.js";

const backendRoot = path.dirname(fileURLToPath(import.meta.url));
const PYTHON_SCRAPER_DIR = path.join(backendRoot, "reddit_scraper");
const PYTHON_SCRIPT = path.join(PYTHON_SCRAPER_DIR, "scrape.py");
const PYTHON_REQUIREMENTS = path.join(PYTHON_SCRAPER_DIR, "requirements.txt");
const BROWSER_WATCH = path.join(backendRoot, "redditAuth", "watch.js");

const SCRAPER_MODE = process.env.REDDIT_SCRAPER_MODE ?? "continuous";
const PYTHON_BIN = process.env.PYTHON_BIN ?? "python3";

const VENV_DIR = path.join(PYTHON_SCRAPER_DIR, ".venv");
const VENV_PYTHON = process.platform === "win32"
  ? path.join(VENV_DIR, "Scripts", "python.exe")
  : path.join(VENV_DIR, "bin", "python");

let scraperProcess = null;
let resolvedPythonExec = null;

function spawnBrowserScraper() {
  if (scraperProcess) return;
  console.log("[reddit] Starting browser scraper (saved session cookies)...");
  scraperProcess = spawn(process.execPath, [BROWSER_WATCH], {
    cwd: backendRoot,
    stdio: "inherit",
    env: { ...process.env },
  });
  bindExitHandlers();
}

function spawnPythonScraper(pythonExec = resolvedPythonExec) {
  if (scraperProcess) return;
  if (!pythonExec) {
    console.error("[reddit] No Python with 'requests' found — cannot start RSS scraper");
    return;
  }
  resolvedPythonExec = pythonExec;
  console.log(`[reddit] Starting Python scraper (${pythonExec}, RSS + JSON, mode: ${SCRAPER_MODE})`);

  scraperProcess = spawn(pythonExec, ["-u", PYTHON_SCRIPT, SCRAPER_MODE], {
    cwd: PYTHON_SCRAPER_DIR,
    stdio: "inherit",
    env: { ...process.env, PYTHONUNBUFFERED: "1" },
  });
  bindExitHandlers();
}

function bindExitHandlers() {
  scraperProcess.on("error", (err) => {
    console.error("[reddit] Failed to start:", err.message);
    scraperProcess = null;
  });

  scraperProcess.on("exit", (code, signal) => {
    scraperProcess = null;
    if (signal === "SIGTERM") {
      console.log("[reddit] Python scraper received SIGTERM (server restart or stop)");
      return;
    }
    if (!isAutoScrapeEnabled()) {
      console.log("[reddit] Auto-scrape is OFF — not restarting");
      return;
    }
    const delay = code === 1 ? 120_000 : 30_000;
    console.log(
      `[reddit] Python scraper exited (code ${code ?? "null"}, signal ${signal ?? "null"}). Retrying in ${delay / 1000}s...`
    );
    setTimeout(startRedditScraper, delay);
  });
}

const PIP_TRUSTED =
  "--trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org";

function pythonCandidates() {
  const list = [];
  for (const bin of [PYTHON_BIN, "python", "python3"]) {
    if (bin && !list.includes(bin)) list.push(bin);
  }
  if (fs.existsSync(VENV_PYTHON) && !list.includes(VENV_PYTHON)) list.push(VENV_PYTHON);
  return list;
}

function resolveWorkingPython(callback) {
  const candidates = pythonCandidates();
  let i = 0;

  function tryNext() {
    if (i >= candidates.length) {
      callback(null);
      return;
    }
    const exe = candidates[i++];
    exec(`"${exe}" -c "import requests"`, { shell: true }, (err) => {
      if (!err) callback(exe);
      else tryNext();
    });
  }

  tryNext();
}

function installPythonDepsThenStart() {
  const tryStart = () => {
    resolveWorkingPython((exe) => {
      if (!exe) {
        console.error("[reddit] No Python with 'requests' found. Install: pip install requests");
        return;
      }
      if (isAutoScrapeEnabled()) spawnPythonScraper(exe);
    });
  };

  if (!fs.existsSync(PYTHON_REQUIREMENTS)) {
    tryStart();
    return;
  }

  const pipFlags = `${PIP_TRUSTED} --quiet --disable-pip-version-check`;
  const setupCmd = fs.existsSync(VENV_PYTHON)
    ? `"${VENV_PYTHON}" -m pip install -r "${PYTHON_REQUIREMENTS}" ${pipFlags}`
    : `"${PYTHON_BIN}" -m venv "${VENV_DIR}" && "${VENV_PYTHON}" -m pip install -r "${PYTHON_REQUIREMENTS}" ${pipFlags}`;

  exec(setupCmd, { shell: true }, (err) => {
    if (err) {
      console.warn("[reddit] pip install failed (university SSL may block PyPI) — trying system Python…");
    }
    tryStart();
  });
}

export function isRedditScraperRunning() {
  return scraperProcess !== null;
}

export function startRedditScraper() {
  if (!isAutoScrapeEnabled()) {
    console.log("[reddit] Auto-scrape is OFF (enable in website)");
    return;
  }
  if (scraperProcess) return;

  restoreSessionFromEnv();

  const forceRss =
    process.env.REDDIT_USE_RSS_ONLY === "true" ||
    process.env.REDDIT_SCRAPER_ENGINE === "rss";
  const browserReady = chromiumInstalled();

  if (!forceRss && hasSession() && browserReady) {
    spawnBrowserScraper();
    return;
  }

  if (hasSession() && !browserReady && !forceRss) {
    console.warn(
      "[reddit] Playwright/Chromium unavailable — using Python RSS scraper (no comment deep-scrape). " +
        "Set REDDIT_USE_RSS_ONLY=true to silence this, or run npm run playwright:install on a network that allows it."
    );
  } else if (forceRss) {
    console.log("[reddit] RSS-only mode (REDDIT_USE_RSS_ONLY=true)");
  } else {
    console.log("[reddit] No session — using public RSS feeds");
  }

  installPythonDepsThenStart();
}

export function stopRedditScraper(reason = "manual") {
  if (scraperProcess) {
    scraperProcess.kill("SIGTERM");
    scraperProcess = null;
    console.log(`[reddit] Scraper stopped (${reason})`);
  }
}

process.on("exit", () => stopRedditScraper("process exit"));
process.on("SIGINT", () => { stopRedditScraper("SIGINT"); process.exit(0); });
process.on("SIGTERM", () => { stopRedditScraper("server SIGTERM — Render deploy/restart"); process.exit(0); });
