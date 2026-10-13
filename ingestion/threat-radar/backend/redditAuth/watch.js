/**
 * Continuous Reddit browser scraper — uses saved session cookies.
 */
import { ensurePlaywrightBrowsers } from "../scripts/ensure-playwright.js";
import { restoreSessionFromEnv } from "./session.js";
import { runWatchCycle } from "./scrape.js";
import { getPollIntervalSeconds, isAutoScrapeEnabled } from "./settings.js";
import { chromiumInstalled } from "./chromiumLaunch.js";

restoreSessionFromEnv();

async function sleepMs(ms) {
  await new Promise((r) => setTimeout(r, ms));
}

async function loop() {
  const ready = await ensurePlaywrightBrowsers();
  if (!ready || !chromiumInstalled()) {
    console.error("[reddit-browser] Chromium not available — exiting");
    process.exit(1);
  }

  while (true) {
    if (!isAutoScrapeEnabled()) {
      console.log("[reddit-browser] Auto-scrape OFF — exiting");
      process.exit(0);
    }

    const intervalSec = getPollIntervalSeconds();
    console.log(`[reddit-browser] Next cycle in ${intervalSec}s after scrape completes`);

    try {
      const count = await runWatchCycle();
      console.log(`[reddit-browser] Cycle done — ${count} new URL(s)`);
    } catch (err) {
      console.error("[reddit-browser] Cycle error:", err.message);
    }

    await sleepMs(getPollIntervalSeconds() * 1000);
  }
}

console.log(`[reddit-browser] Watch mode — interval ${getPollIntervalSeconds()}s`);
loop();
