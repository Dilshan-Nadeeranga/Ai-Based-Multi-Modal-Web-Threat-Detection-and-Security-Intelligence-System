import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const backendRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
export const SESSION_FILE = path.join(backendRoot, "data", "reddit_session.json");

export function hasSession() {
  return fs.existsSync(SESSION_FILE);
}

export function loadSession() {
  if (!hasSession()) return null;
  return JSON.parse(fs.readFileSync(SESSION_FILE, "utf-8"));
}

export function saveSession(storageState) {
  fs.mkdirSync(path.dirname(SESSION_FILE), { recursive: true });
  fs.writeFileSync(SESSION_FILE, JSON.stringify(storageState, null, 2), "utf-8");
}

export function clearSession() {
  if (fs.existsSync(SESSION_FILE)) fs.unlinkSync(SESSION_FILE);
}

/** Accept Playwright storageState or a plain cookies array. */
export function normalizeSessionImport(data) {
  if (Array.isArray(data)) {
    return { cookies: data, origins: [] };
  }
  if (data?.cookies && Array.isArray(data.cookies)) {
    return { cookies: data.cookies, origins: data.origins ?? [] };
  }
  throw new Error(
    "Invalid format. Paste contents of backend/data/reddit_session.json " +
    "or a JSON array of cookies."
  );
}

function hasRedditAuthCookies(storageState) {
  return storageState?.cookies?.some((c) =>
    c.name === "reddit_session" || c.name === "token_v2"
  );
}

function decodeSessionEnv(raw) {
  const trimmed = String(raw).trim();
  if (!trimmed) throw new Error("REDDIT_SESSION_B64 is empty");

  // Normal: base64 of reddit_session.json
  try {
    const decoded = Buffer.from(trimmed, "base64").toString("utf-8");
    const parsed = JSON.parse(decoded);
    return normalizeSessionImport(parsed);
  } catch {
    /* fall through — user may have pasted raw JSON by mistake */
  }

  // Mistake: pasted raw JSON into Render env instead of base64
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    return normalizeSessionImport(JSON.parse(trimmed));
  }

  throw new Error(
    "REDDIT_SESSION_B64 must be base64 from: npm run reddit:encode (not raw JSON unless valid JSON)"
  );
}

/**
 * Restore session from REDDIT_SESSION_B64 env (for cloud deploy).
 * When set, always overwrites disk file on boot so stale files don't block restore.
 */
export function restoreSessionFromEnv() {
  const b64 = process.env.REDDIT_SESSION_B64;
  if (!b64?.trim()) return false;

  try {
    const storageState = decodeSessionEnv(b64);
    if (!hasRedditAuthCookies(storageState)) {
      console.error("[reddit-auth] REDDIT_SESSION_B64 has no reddit_session / token_v2 cookie");
      return false;
    }
    saveSession(storageState);
    console.log("[reddit-auth] Session restored from REDDIT_SESSION_B64 →", SESSION_FILE);
    return true;
  } catch (err) {
    console.error("[reddit-auth] Failed to restore REDDIT_SESSION_B64:", err.message);
    return false;
  }
}
