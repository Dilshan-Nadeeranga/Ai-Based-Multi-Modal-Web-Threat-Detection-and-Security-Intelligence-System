/**
 * Shared Python / venv setup for scraper and auth scripts.
 */

import { exec } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const backendRoot = path.dirname(fileURLToPath(import.meta.url));

export const SCRAPER_DIR = path.join(backendRoot, "scraper");
export const REQUIREMENTS = path.join(SCRAPER_DIR, "requirements.txt");

const VENV_DIR = path.join(SCRAPER_DIR, ".venv");
export const VENV_PYTHON =
  process.platform === "win32"
    ? path.join(VENV_DIR, "Scripts", "python.exe")
    : path.join(VENV_DIR, "bin", "python");

const PYTHON_BIN = process.env.PYTHON_BIN ?? "python3";

let depsPromise = null;

function runShell(cmd) {
  return new Promise((resolve, reject) => {
    exec(cmd, { shell: true }, (err, _stdout, stderr) => {
      if (err) reject(new Error(stderr?.trim() || err.message));
      else resolve();
    });
  });
}

function venvUsable() {
  return fs.existsSync(VENV_PYTHON);
}

/** Remove partial/broken .venv left from a failed deploy. */
function removeStaleVenv() {
  if (!fs.existsSync(VENV_DIR)) return;
  if (venvUsable()) return;
  console.log("[python] Removing broken .venv directory...");
  fs.rmSync(VENV_DIR, { recursive: true, force: true });
}

async function createVenv() {
  removeStaleVenv();
  if (venvUsable()) return;
  console.log("[python] Creating virtual environment...");
  await runShell(`"${PYTHON_BIN}" -m venv "${VENV_DIR}"`);
}

async function pipInstall() {
  await runShell(
    `"${VENV_PYTHON}" -m pip install -r "${REQUIREMENTS}" --quiet --disable-pip-version-check`
  );
}

async function setupPythonDeps() {
  if (!fs.existsSync(REQUIREMENTS)) return false;

  try {
    await createVenv();
    await pipInstall();
    return true;
  } catch (firstErr) {
    console.warn("[python] Setup failed, retrying with fresh venv:", firstErr.message);
    if (fs.existsSync(VENV_DIR)) {
      fs.rmSync(VENV_DIR, { recursive: true, force: true });
    }
    await createVenv();
    await pipInstall();
    return true;
  }
}

export function getPython() {
  return venvUsable() ? VENV_PYTHON : PYTHON_BIN;
}

/** Install Python deps once (async). Retries after removing a broken venv. */
export function ensurePythonDeps() {
  if (!depsPromise) {
    depsPromise = setupPythonDeps().catch((err) => {
      depsPromise = null;
      console.error("[python] Dependency setup failed:", err.message);
      return false;
    });
  }
  return depsPromise;
}
