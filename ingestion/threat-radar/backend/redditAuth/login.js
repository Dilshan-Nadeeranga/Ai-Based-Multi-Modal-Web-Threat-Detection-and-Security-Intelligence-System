import "../playwright-env.js";
import { launchChromium } from "./chromiumLaunch.js";
import { saveSession, hasSession, SESSION_FILE, loadSession } from "./session.js";
import { supportsBrowserLogin } from "./capabilities.js";

const LOGIN_URL = "https://www.reddit.com/login/";
const HEADLESS = process.env.REDDIT_LOGIN_HEADLESS !== "false";

async function fillLoginForm(page, username, password) {
  const userSelectors = [
    'input[name="username"]',
    "#login-username",
    'input[autocomplete="username"]',
  ];
  const passSelectors = [
    'input[name="password"]',
    "#login-password",
    'input[type="password"]',
  ];

  let filledUser = false;
  for (const sel of userSelectors) {
    const el = page.locator(sel).first();
    if (await el.count()) {
      await el.fill(username);
      filledUser = true;
      break;
    }
  }
  if (!filledUser) throw new Error("Could not find Reddit username field");

  let filledPass = false;
  for (const sel of passSelectors) {
    const el = page.locator(sel).first();
    if (await el.count()) {
      await el.fill(password);
      filledPass = true;
      break;
    }
  }
  if (!filledPass) throw new Error("Could not find Reddit password field");

  const submit = page.locator('button[type="submit"], button:has-text("Log In")').first();
  await submit.click();
}

async function waitForLogin(page, timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const url = page.url();
    const html = await page.content();

    if (html.includes("verifying you're a human") || html.includes("CAPTCHA")) {
      throw new Error(
        "Reddit CAPTCHA detected. Set REDDIT_LOGIN_HEADLESS=false and try again locally, " +
        "or import a saved session via the website."
      );
    }

    if (!url.includes("/login") && !url.includes("account/register")) {
      const cookies = await page.context().cookies();
      if (cookies.some((c) => c.name === "reddit_session" || c.name === "token_v2")) {
        return true;
      }
    }

    await page.waitForTimeout(1500);
  }
  return false;
}

/**
 * Log in with Reddit username/email + password; save browser cookies to disk.
 */
export async function loginWithCredentials(username, password) {
  let browser;
  try {
    browser = await launchChromium(HEADLESS);
  } catch (err) {
    const msg = err?.message ?? String(err);
    if (msg.includes("Executable doesn't exist") || msg.includes("browserType.launch")) {
      throw new Error(
        "Playwright Chromium is not installed on the server. " +
        "On Render: redeploy after build installs Chromium, or use “Import session JSON” / REDDIT_SESSION_B64. " +
        "On PC: cd backend && npx playwright install chromium"
      );
    }
    throw err;
  }

  const context = await browser.newContext({
    userAgent: process.env.REDDIT_USER_AGENT ||
      "ThreatRadar/1.0 (scam URL monitor)",
  });
  const page = await context.newPage();

  try {
    await page.goto(LOGIN_URL, { waitUntil: "domcontentloaded", timeout: 60_000 });
    await page.waitForTimeout(2000);
    await fillLoginForm(page, username, password);

    const ok = await waitForLogin(page);
    if (!ok) {
      throw new Error("Login timed out. Check username/password or complete CAPTCHA.");
    }

    const storageState = await context.storageState();
    saveSession(storageState);

    let displayName = username;
    try {
      await page.goto("https://www.reddit.com/", { waitUntil: "domcontentloaded" });
      displayName = await page.locator('[id="email-collection-tooltip-id"]').first()
        .getAttribute("aria-label")
        .catch(() => null) || username;
    } catch { /* ignore */ }

    return {
      success: true,
      step: "done",
      username: displayName,
      message: "Reddit session saved",
      sessionFile: SESSION_FILE,
    };
  } finally {
    await browser.close();
  }
}

/**
 * Open a visible browser — user logs in manually (CAPTCHA / 2FA safe).
 * Auto-saves cookies when login is detected.
 */
export async function loginWithBrowser() {
  let browser;
  try {
    browser = await launchChromium(false);
  } catch (err) {
    const msg = err?.message ?? String(err);
    if (msg.includes("Executable doesn't exist") || msg.includes("browserType.launch")) {
      throw new Error(
        "Playwright browser not installed. Run: cd backend && npx playwright install chromium"
      );
    }
    throw err;
  }

  const context = await browser.newContext({
    userAgent: process.env.REDDIT_USER_AGENT ||
      "ThreatRadar/1.0 (scam URL monitor)",
  });
  const page = await context.newPage();

  await page.goto(LOGIN_URL, { waitUntil: "domcontentloaded" });
  console.log("\n========================================");
  console.log("  Log in to Reddit in the browser window");
  console.log("  (complete CAPTCHA / 2FA if asked)");
  console.log("  Waiting for login — do not close this terminal...");
  console.log("========================================\n");

  const deadline = Date.now() + 10 * 60 * 1000;
  while (Date.now() < deadline) {
    const cookies = await context.cookies();
    const url = page.url();
    const loggedIn = cookies.some((c) =>
      c.name === "reddit_session" || c.name === "token_v2"
    );

    if (loggedIn && !url.includes("/login")) {
      const storageState = await context.storageState();
      saveSession(storageState);
      await browser.close();
      console.log(`\n[ok] Session saved → ${SESSION_FILE}\n`);
      return { success: true, step: "done", message: "Reddit session saved from browser" };
    }

    await page.waitForTimeout(2000);
  }

  await browser.close();
  throw new Error("Login timed out after 10 minutes.");
}

export async function getSessionStatus() {
  if (!hasSession()) {
    return { success: false, step: "none", message: "Not logged in" };
  }

  const session = loadSession();
  const hasRedditCookie = session?.cookies?.some((c) =>
    c.name === "reddit_session" || c.name === "token_v2"
  );
  if (!hasRedditCookie) {
    return { success: false, step: "none", message: "Session file invalid — import again" };
  }

  let browser;
  try {
    browser = await launchChromium(true);
  } catch (err) {
    const msg = err?.message ?? String(err);
    if (msg.includes("Executable doesn't exist") || msg.includes("browserType.launch")) {
      return {
        success: true,
        step: "done",
        message: supportsBrowserLogin()
          ? "Session saved (install Playwright to verify: npx playwright install chromium)"
          : "Session imported on server",
      };
    }
    throw err;
  }

  const context = await browser.newContext({ storageState: SESSION_FILE });
  const page = await context.newPage();

  try {
    await page.goto("https://www.reddit.com/", { waitUntil: "domcontentloaded", timeout: 30_000 });
    const url = page.url();
    const html = await page.content();

    if (url.includes("/login") || html.toLowerCase().includes("log in")) {
      return { success: false, step: "none", message: "Session expired — log in again" };
    }

    return { success: true, step: "done", message: "Reddit session active" };
  } catch (err) {
    return { success: false, step: "error", message: err.message };
  } finally {
    await browser.close();
  }
}
