import "../playwright-env.js";
import fs from "fs";
import { chromium } from "playwright";

/** Args required on Linux containers (Render). */
export function chromiumArgs() {
  if (
    process.env.RENDER === "true" ||
    process.env.CI === "true" ||
    process.platform === "linux"
  ) {
    return ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"];
  }
  return [];
}

export function chromiumExecutablePath() {
  return chromium.executablePath();
}

export function chromiumInstalled() {
  try {
    const exe = chromium.executablePath();
    return Boolean(exe && fs.existsSync(exe));
  } catch {
    return false;
  }
}

export async function launchChromium(headless = true) {
  return chromium.launch({ headless, args: chromiumArgs() });
}
