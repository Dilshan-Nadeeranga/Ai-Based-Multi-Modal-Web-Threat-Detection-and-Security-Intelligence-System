import "../playwright-env.js";
import { chromiumInstalled } from "./chromiumLaunch.js";

/** True when backend runs on a cloud host (no visible browser possible). */
export function isCloudHost() {
  return (
    process.env.RENDER === "true" ||
    process.env.VERCEL === "1" ||
    process.env.FLY_APP_NAME != null ||
    process.env.RAILWAY_ENVIRONMENT != null
  );
}

/** Browser login only works on your PC where a window can open. */
export function supportsBrowserLogin() {
  if (process.env.REDDIT_BROWSER_LOGIN === "false") return false;
  if (isCloudHost()) return false;
  return true;
}

export function supportsCredentialLogin() {
  if (process.env.REDDIT_CREDENTIAL_LOGIN === "false") return false;
  return playwrightReady();
}

/** Whether Playwright Chromium binary exists (required for password login + scraping). */
export function playwrightReady() {
  return chromiumInstalled();
}

export function playwrightMissingMessage() {
  return (
    "Playwright Chromium is not installed on this server. " +
    "Use “Import session JSON” below, or set REDDIT_SESSION_B64 on Render. " +
    "On Render: Build Command must be `npm install && npm run build`, remove PLAYWRIGHT_BROWSERS_PATH=0 if set."
  );
}

export function browserLoginBlockedMessage() {
  return (
    "Browser login only works when the backend runs on your PC (localhost). " +
    "On Vercel/Render: use “Paste session JSON” below, or set REDDIT_SESSION_B64 on your Render backend."
  );
}
