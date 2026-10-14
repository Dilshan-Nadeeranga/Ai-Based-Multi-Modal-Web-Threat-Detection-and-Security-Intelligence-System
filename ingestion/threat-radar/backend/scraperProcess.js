/**
 * Manages the Python Telegram scraper.
 *
 * Modes (SCRAPER_MODE):
 *   scheduled  — run batch scrape every N minutes (default, best for Render)
 *   continuous — discover + batch + real-time watch (long-running)
 *   watch      — real-time only
 *   batch      — one-shot batch (manual / API trigger)
 */

import { spawn } from "child_process";
import fs from "fs";
import path from "path";
import { ensurePythonDeps, getPython, SCRAPER_DIR } from "./pythonEnv.js";

const SCRAPER_SCRIPT = path.join(SCRAPER_DIR, "scrape.py");
const SCRAPER_ENABLED = process.env.SCRAPER_ENABLED === "true";
const SCRAPER_MODE = process.env.SCRAPER_MODE ?? "scheduled";
const SESSION_NAME = process.env.TELEGRAM_SESSION_NAME ?? "scraper_session";
const ON_RENDER = process.env.RENDER === "true";
const ALLOW_LOCAL = process.env.SCRAPER_ALLOW_LOCAL === "true";
const RESTORE_SESSION_B64 = process.env.TELEGRAM_RESTORE_SESSION_B64 === "true";
const INTERVAL_MINUTES = Number(process.env.SCRAPER_INTERVAL_MINUTES ?? 10);
const START_DELAY_SECONDS = Number(process.env.SCRAPER_START_DELAY_SECONDS ?? 30);

const sessionPath = () => path.join(SCRAPER_DIR, `${SESSION_NAME}.session`);

let scraperProcess = null;
let sessionDead = false;
let batchRunning = false;
let startTimer = null;
let intervalTimer = null;

export function hasSessionFile() {
  return fs.existsSync(sessionPath());
}

export function resetSessionDead() {
  sessionDead = false;
}

export function readSessionB64() {
  const p = sessionPath();
  if (!fs.existsSync(p)) return null;
  return fs.readFileSync(p).toString("base64");
}

function shouldRunScraper() {
  if (!SCRAPER_ENABLED) return false;

  if (!ON_RENDER && !ALLOW_LOCAL) {
    console.log(
      "[scraper] Skipped on local machine.\n" +
        "  Run scraper on Render only, or set SCRAPER_ALLOW_LOCAL=true for dev."
    );
    return false;
  }

  if (sessionDead) {
    console.log("[scraper] Session invalidated. Log in via frontend Telegram Login.");
    return false;
  }

  return true;
}

function restoreSessionFile() {
  if (!RESTORE_SESSION_B64) return false;
  const b64 = process.env.TELEGRAM_SESSION_B64;
  if (!b64) return false;
  if (fs.existsSync(sessionPath())) return true;
  try {
    fs.writeFileSync(sessionPath(), Buffer.from(b64, "base64"));
    console.log("[scraper] Session restored from TELEGRAM_SESSION_B64 (opt-in)");
    return true;
  } catch (err) {
    console.error("[scraper] Failed to restore session:", err.message);
    return false;
  }
}

function clearScheduleTimers() {
  if (startTimer) {
    clearTimeout(startTimer);
    startTimer = null;
  }
  if (intervalTimer) {
    clearInterval(intervalTimer);
    intervalTimer = null;
  }
}

function handleProcessExit(code, signal, { retryLongRunning = false } = {}) {
  scraperProcess = null;
  batchRunning = false;

  if (signal === "SIGTERM") return;

  if (code === 2) {
    sessionDead = true;
    clearScheduleTimers();
    console.error(
      "[scraper] Session killed by Telegram (dual login).\n" +
        "  Log in again via frontend → Telegram Login"
    );
    return;
  }

  if (!retryLongRunning || SCRAPER_MODE === "scheduled") return;

  if (!shouldRunScraper()) return;

  const delay = code === 1 ? 120_000 : 30_000;
  console.log(`[scraper] Exited (code ${code}). Retrying in ${delay / 1000}s...`);
  setTimeout(() => startLongRunningScraper(), delay);
}

function spawnPython(mode) {
  const pythonExec = getPython();
  console.log(`[scraper] Starting Python scraper (mode: ${mode})...`);

  scraperProcess = spawn(pythonExec, [SCRAPER_SCRIPT, mode], {
    cwd: SCRAPER_DIR,
    stdio: "inherit",
    env: { ...process.env },
  });

  scraperProcess.on("error", (err) => {
    console.error("[scraper] Failed to start:", err.message);
    batchRunning = false;
    scraperProcess = null;
  });

  scraperProcess.on("exit", (code, signal) => {
    if (SCRAPER_MODE === "scheduled" || mode === "batch") {
      console.log(`[scraper] Batch run finished (exit ${code ?? signal})`);
      handleProcessExit(code, signal, { retryLongRunning: false });
    } else {
      handleProcessExit(code, signal, { retryLongRunning: true });
    }
  });

  return scraperProcess;
}

/** Run one batch scrape (used by schedule + manual API). */
export async function runBatchOnce() {
  if (!shouldRunScraper()) return { ok: false, reason: "scraper disabled" };
  if (!hasSessionFile()) return { ok: false, reason: "not logged in" };
  if (batchRunning) return { ok: false, reason: "already running" };

  restoreSessionFile();
  batchRunning = true;

  await ensurePythonDeps();
  spawnPython("batch");
  return { ok: true };
}

function startLongRunningScraper() {
  if (!shouldRunScraper()) return;
  restoreSessionFile();

  if (!hasSessionFile()) {
    console.log("[scraper] Waiting for Telegram login via frontend.");
    return;
  }

  if (scraperProcess || batchRunning) {
    console.log("[scraper] Already running.");
    return;
  }

  ensurePythonDeps().then((ok) => {
    if (ok) console.log("[scraper] Python dependencies ready.");
    spawnPython(SCRAPER_MODE === "batch" ? "batch" : SCRAPER_MODE);
  });
}

function startScheduledScraper() {
  if (!shouldRunScraper()) {
    if (!SCRAPER_ENABLED) console.log("[scraper] Disabled (SCRAPER_ENABLED=false)");
    return;
  }

  restoreSessionFile();

  if (!hasSessionFile()) {
    console.log(
      "[scraper] Scheduled mode — waiting for Telegram login.\n" +
        `  First batch runs ${START_DELAY_SECONDS}s after login.`
    );
    return;
  }

  if (startTimer || intervalTimer) return;

  const intervalMs = INTERVAL_MINUTES * 60 * 1000;
  const delayMs = START_DELAY_SECONDS * 1000;

  console.log(
    `[scraper] Scheduled batch every ${INTERVAL_MINUTES} min ` +
      `(first run in ${START_DELAY_SECONDS}s after server start)`
  );

  startTimer = setTimeout(() => {
    startTimer = null;
    runBatchOnce();
    intervalTimer = setInterval(() => runBatchOnce(), intervalMs);
  }, delayMs);
}

/** Start scraper on server boot (mode from SCRAPER_MODE). */
export function startScraper() {
  if (SCRAPER_MODE === "scheduled") {
    startScheduledScraper();
  } else {
    startLongRunningScraper();
  }
}

/** After frontend Telegram login — start schedule or long-running scraper. */
export function restartScraperAfterLogin() {
  resetSessionDead();
  stopScraper();
  startScraper();
}

export function stopScraper() {
  clearScheduleTimers();
  if (scraperProcess) {
    scraperProcess.kill("SIGTERM");
    scraperProcess = null;
  }
  batchRunning = false;
}

process.on("exit", stopScraper);
process.on("SIGINT", () => {
  stopScraper();
  process.exit(0);
});
process.on("SIGTERM", () => {
  stopScraper();
  process.exit(0);
});
