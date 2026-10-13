import { execSync } from "child_process";
import path from "path";
import { backendRootFrom } from "../paths.js";
import {
  chromiumExecutablePath,
  chromiumInstalled,
} from "../redditAuth/chromiumLaunch.js";

const backendRoot = backendRootFrom(import.meta.url);
const installScript = path.join(backendRoot, "scripts", "install-playwright.js");

/**
 * Ensure Chromium exists before starting the Reddit browser scraper.
 * Build-time install can be lost on Render; this re-downloads if needed.
 */
export async function ensurePlaywrightBrowsers() {
  if (chromiumInstalled()) {
    console.log(`[playwright] Ready: ${chromiumExecutablePath()}`);
    return true;
  }

  console.warn(
    "[playwright] Chromium missing at runtime — downloading now (1–3 min on first boot)…"
  );

  try {
    execSync(`node "${installScript}" --required`, {
      stdio: "inherit",
      cwd: backendRoot,
      env: { ...process.env },
    });
  } catch (err) {
    console.error("[playwright] Runtime install failed:", err.message);
    return false;
  }

  const ok = chromiumInstalled();
  if (ok) {
    console.log(`[playwright] Ready after install: ${chromiumExecutablePath()}`);
  } else {
    console.error("[playwright] Still missing after install");
  }
  return ok;
}
