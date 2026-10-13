import { Router } from "express";
import { clearSession, hasSession, normalizeSessionImport, saveSession } from "../redditAuth/session.js";
import {
  getSessionStatus,
  loginWithCredentials,
} from "../redditAuth/login.js";
import {
  getBrowserLoginJob,
  resetBrowserLoginJob,
  startBrowserLoginJob,
} from "../redditAuth/browserLoginJob.js";
import {
  browserLoginBlockedMessage,
  isCloudHost,
  supportsBrowserLogin,
  supportsCredentialLogin,
  playwrightReady,
  playwrightMissingMessage,
} from "../redditAuth/capabilities.js";

export const redditAuthRouter = Router();

let loginInProgress = false;

/** GET /api/reddit-auth/capabilities */
redditAuthRouter.get("/capabilities", (_req, res) => {
  try {
    const envSession = Boolean(process.env.REDDIT_SESSION_B64?.trim());
    res.json({
      browserLogin: supportsBrowserLogin(),
      credentialLogin: supportsCredentialLogin(),
      playwrightReady: playwrightReady(),
      sessionImport: true,
      cloud: isCloudHost(),
      hasSessionFile: hasSession(),
      redditSessionB64Set: envSession,
      message: supportsBrowserLogin()
        ? "Browser login available (backend on your PC)."
        : playwrightReady()
          ? browserLoginBlockedMessage()
          : playwrightMissingMessage(),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** GET /api/reddit-auth/status */
redditAuthRouter.get("/status", async (_req, res) => {
  try {
    if (!hasSession()) {
      return res.json({ success: false, step: "none", message: "Not logged in" });
    }
    res.json(await getSessionStatus());
  } catch (err) {
    res.status(500).json({ success: false, step: "error", message: err.message });
  }
});

/**
 * POST /api/reddit-auth/browser-login/start
 * Opens a visible browser on the machine running the backend (local dev).
 */
redditAuthRouter.post("/browser-login/start", (_req, res) => {
  if (!supportsBrowserLogin()) {
    return res.status(501).json({
      success: false,
      step: "error",
      message: browserLoginBlockedMessage(),
    });
  }
  try {
    const result = startBrowserLoginJob();
    if (!result.started) {
      return res.status(409).json({ success: false, step: "waiting", message: result.message });
    }
    res.json({
      success: true,
      step: "browser_open",
      message: result.message,
    });
  } catch (err) {
    res.status(500).json({ success: false, step: "error", message: err.message });
  }
});

/** GET /api/reddit-auth/browser-login/status */
redditAuthRouter.get("/browser-login/status", async (_req, res) => {
  const job = getBrowserLoginJob();

  if (job.status === "done" || (job.status === "idle" && hasSession())) {
    resetBrowserLoginJob();
    const status = hasSession() ? await getSessionStatus() : { success: false, step: "none" };
    return res.json({ ...status, browserLogin: "done" });
  }

  if (job.status === "error") {
    const message = job.message;
    resetBrowserLoginJob();
    return res.json({ success: false, step: "error", message, browserLogin: "error" });
  }

  if (job.status === "waiting") {
    return res.json({
      success: false,
      step: "browser_open",
      message: job.message ?? "Complete login in the browser window…",
      browserLogin: "waiting",
    });
  }

  res.json({ success: false, step: "none", message: "Not logged in", browserLogin: "idle" });
});

/**
 * POST /api/reddit-auth/login
 * Body: { username: "...", password: "..." }
 * Saves browser cookies (Playwright storageState) to backend/data/reddit_session.json
 */
redditAuthRouter.post("/login", async (req, res) => {
  const username = String(req.body?.username ?? "").trim();
  const password = String(req.body?.password ?? "");

  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: "username and password are required",
    });
  }

  if (loginInProgress) {
    return res.status(409).json({ success: false, message: "Login already in progress" });
  }

  if (!playwrightReady()) {
    return res.status(503).json({
      success: false,
      step: "error",
      message: playwrightMissingMessage(),
    });
  }

  loginInProgress = true;
  try {
    const result = await loginWithCredentials(username, password);
    res.json(result);
  } catch (err) {
    res.status(400).json({ success: false, step: "error", message: err.message });
  } finally {
    loginInProgress = false;
  }
});

/**
 * POST /api/reddit-auth/import-session
 * Body: Playwright storageState { cookies, origins } OR cookies array [...]
 */
redditAuthRouter.post("/import-session", async (req, res) => {
  try {
    const storageState = normalizeSessionImport(req.body);
    const hasRedditCookie = storageState.cookies.some((c) =>
      c.name === "reddit_session" || c.name === "token_v2"
    );
    if (!hasRedditCookie) {
      return res.status(400).json({
        success: false,
        message: "No reddit_session cookie found. Log in to Reddit first, then export cookies.",
      });
    }
    saveSession(storageState);
    res.json({ success: true, step: "done", message: "Reddit session imported" });
  } catch (err) {
    res.status(400).json({ success: false, message: err.message });
  }
});

/** POST /api/reddit-auth/logout */
redditAuthRouter.post("/logout", async (_req, res) => {
  clearSession();
  res.json({ success: true, step: "none", message: "Logged out" });
});
