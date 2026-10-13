import cron from "node-cron";
import { config } from "./config.js";
import { filterLatestDownload } from "./domainFilter.js";
import { runDownload } from "./downloadJob.js";

async function dailyJob() {
  console.log(
    `[scheduler] Downloading ${config.dailyZone} (${config.dailyFormat})...`
  );
  try {
    const result = await runDownload({
      zone: config.dailyZone,
      format: config.dailyFormat,
      dated: true,
    });
    const detail =
      result.lineCount != null
        ? `${result.lineCount.toLocaleString()} domains`
        : `${(result.bytes / 1024 / 1024).toFixed(2)} MB`;
    console.log(`[scheduler] Saved ${result.saved} (${detail})`);

    if (config.dailyFormat === "text" && result.path) {
      try {
        const filtered = await filterLatestDownload();
        console.log(
          `[scheduler] Filtered ${filtered.matchedCount} suspicious domains`
        );
        result.filtered = {
          saved: filtered.saved,
          matchedCount: filtered.matchedCount,
          totalScanned: filtered.totalScanned,
        };
      } catch (filterErr) {
        console.warn("[scheduler] Domain filter skipped:", filterErr.message);
      }
    }

    return result;
  } catch (err) {
    console.error("[scheduler] Failed:", err.message ?? err);
    throw err;
  }
}

export function startScheduler() {
  if (!config.autoDownload) {
    console.log("[scheduler] Auto-download off (AUTO_DOWNLOAD=false)");
    return;
  }

  if (!cron.validate(config.downloadCron)) {
    console.error("[scheduler] Invalid DOWNLOAD_CRON:", config.downloadCron);
    return;
  }

  cron.schedule(config.downloadCron, () => {
    dailyJob().catch(() => {});
  }, { timezone: "UTC" });

  console.log(
    `[scheduler] Daily download: ${config.downloadCron} UTC → backend/data/downloads/`
  );
}

export { dailyJob };
