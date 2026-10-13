import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

const backendRoot = path.dirname(fileURLToPath(import.meta.url));

dotenv.config({ path: path.join(backendRoot, ".env") });

export const config = {
  token: process.env.DOMAINS_MONITOR_TOKEN ?? "",
  apiBase: process.env.API_BASE_URL ?? "https://domains-monitor.com/api/v1",
  timeoutMs: Number(process.env.HTTP_TIMEOUT_SECONDS ?? 600) * 1000,
  port: Number(process.env.PORT ?? 4000),
  downloadDir: path.resolve(
    backendRoot,
    process.env.DOWNLOAD_DIR ?? "data/downloads"
  ),
  autoDownload: process.env.AUTO_DOWNLOAD !== "false",
  downloadCron: process.env.DOWNLOAD_CRON ?? "0 6 * * *",
  dailyZone: process.env.DAILY_ZONE ?? "dailyupdate",
  dailyFormat: process.env.DAILY_FORMAT ?? "text",
};
