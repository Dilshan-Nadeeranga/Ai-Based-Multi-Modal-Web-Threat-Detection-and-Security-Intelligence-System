/**
 * Configure Playwright before any `import "playwright"`.
 * Uses backend/.playwright-browsers (persists on Render; avoids node_modules/.local-browsers issues).
 */
import path from "path";
import { fileURLToPath } from "url";
import { backendRootFromBackendFile } from "./paths.js";

const backendRoot = backendRootFromBackendFile(import.meta.url);

if (
  !process.env.PLAYWRIGHT_BROWSERS_PATH ||
  process.env.PLAYWRIGHT_BROWSERS_PATH === "0"
) {
  process.env.PLAYWRIGHT_BROWSERS_PATH = path.join(backendRoot, ".playwright-browsers");
}

if (process.env.PLAYWRIGHT_SKIP_BROWSER_GC === undefined) {
  process.env.PLAYWRIGHT_SKIP_BROWSER_GC = "1";
}

if (process.env.PLAYWRIGHT_DOWNLOAD_CONNECTION_TIMEOUT === undefined) {
  process.env.PLAYWRIGHT_DOWNLOAD_CONNECTION_TIMEOUT = "300000";
}
