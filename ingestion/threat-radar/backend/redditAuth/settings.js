import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const backendRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const SETTINGS_FILE = path.join(backendRoot, "data", "reddit_settings.json");

const VALID_SEARCH_SCOPES = ["global", "subreddits", "both"];
const MIN_POLL_SECONDS = 60;
const MAX_POLL_SECONDS = 3600;
const DEFAULT_POLL_SECONDS = Number(process.env.REDDIT_POLL_INTERVAL_SECONDS) || 300;

function defaultSettings() {
  return {
    autoScrape: process.env.REDDIT_SCRAPER_ENABLED === "true",
    searchScope: "global",
    pollIntervalSeconds: DEFAULT_POLL_SECONDS,
  };
}

export function getRedditSettings() {
  try {
    const data = JSON.parse(fs.readFileSync(SETTINGS_FILE, "utf-8"));
    return { ...defaultSettings(), ...data };
  } catch {
    const settings = defaultSettings();
    writeRedditSettings(settings);
    return settings;
  }
}

export function writeRedditSettings(settings) {
  fs.mkdirSync(path.dirname(SETTINGS_FILE), { recursive: true });
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2), "utf-8");
}

export function isAutoScrapeEnabled() {
  return getRedditSettings().autoScrape === true;
}

export function getSearchScope() {
  const scope = getRedditSettings().searchScope;
  return VALID_SEARCH_SCOPES.includes(scope) ? scope : "global";
}

export function getPollIntervalSeconds() {
  const n = Number(getRedditSettings().pollIntervalSeconds);
  if (!Number.isFinite(n)) return DEFAULT_POLL_SECONDS;
  return Math.min(MAX_POLL_SECONDS, Math.max(MIN_POLL_SECONDS, Math.round(n)));
}

export function setAutoScrape(enabled) {
  const settings = { ...getRedditSettings(), autoScrape: Boolean(enabled) };
  writeRedditSettings(settings);
  return settings;
}

export function updateRedditSettings(partial) {
  const settings = { ...getRedditSettings(), ...partial };

  if (partial.searchScope && !VALID_SEARCH_SCOPES.includes(partial.searchScope)) {
    throw new Error(`searchScope must be one of: ${VALID_SEARCH_SCOPES.join(", ")}`);
  }
  if (partial.pollIntervalSeconds !== undefined) {
    const n = Number(partial.pollIntervalSeconds);
    if (!Number.isFinite(n) || n < MIN_POLL_SECONDS || n > MAX_POLL_SECONDS) {
      throw new Error(`pollIntervalSeconds must be between ${MIN_POLL_SECONDS} and ${MAX_POLL_SECONDS}`);
    }
    settings.pollIntervalSeconds = Math.round(n);
  }

  writeRedditSettings(settings);
  return settings;
}
