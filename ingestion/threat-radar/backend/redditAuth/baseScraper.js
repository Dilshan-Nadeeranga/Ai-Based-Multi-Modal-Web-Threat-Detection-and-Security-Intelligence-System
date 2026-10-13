import "../playwright-env.js";
import { launchChromium } from "./chromiumLaunch.js";
import { SESSION_FILE } from "./session.js";

export function scrapeHeadless() {
  if (process.env.REDDIT_SCRAPE_HEADLESS !== undefined) {
    return process.env.REDDIT_SCRAPE_HEADLESS !== "false";
  }
  return process.env.REDDIT_LOGIN_HEADLESS !== "false";
}

export function redditUserAgent() {
  return process.env.REDDIT_USER_AGENT || "ThreatRadar/1.0 (scam URL monitor)";
}

export async function launchRedditBrowser() {
  const browser = await launchChromium(scrapeHeadless());
  const context = await browser.newContext({
    storageState: SESSION_FILE,
    userAgent: redditUserAgent(),
    viewport: { width: 1280, height: 900 },
  });
  const page = await context.newPage();
  return { browser, context, page };
}

export async function autoScroll(page, maxScrolls = 5) {
  for (let i = 0; i < maxScrolls; i++) {
    await page.evaluate(() => window.scrollBy(0, window.innerHeight));
    await page.waitForTimeout(1200);
  }
}

export async function expandComments(page) {
  const expandTexts = [
    "more comments",
    "view more comments",
    "view all comments",
    "show more",
    "show more replies",
    "more replies",
    "continue thread",
    "more reply",
  ];

  for (let round = 0; round < 3; round++) {
    let clicked = false;
    for (const text of expandTexts) {
      try {
        const btn = page.locator(`button:has-text("${text}")`).first();
        if (await btn.count()) {
          await btn.click({ timeout: 3000 });
          await page.waitForTimeout(1200);
          clicked = true;
        }
      } catch { /* optional */ }
    }
    if (!clicked) break;
  }
}

/** Extract text + hrefs from selectors, including inside shadow roots. */
export async function extractSelectorBlocks(page, selectors) {
  return page.evaluate((sels) => {
    const results = [];
    const seen = new Set();

    function collectHrefs(root, hrefs) {
      if (!root) return;
      root.querySelectorAll?.("a[href]")?.forEach((a) => {
        const href = a.getAttribute("href");
        if (href) hrefs.push(href);
      });
      root.querySelectorAll?.("*")?.forEach((el) => {
        if (el.shadowRoot) collectHrefs(el.shadowRoot, hrefs);
      });
    }

    function walk(root) {
      if (!root) return;
      for (const sel of sels) {
        root.querySelectorAll?.(sel)?.forEach((el) => {
          const text = (el.innerText || el.textContent || "").trim();
          const hrefs = [];
          collectHrefs(el, hrefs);
          if (el.shadowRoot) collectHrefs(el.shadowRoot, hrefs);
          for (const attr of ["content-href", "permalink", "post-url", "href", "call-to-action-href"]) {
            const val = el.getAttribute?.(attr);
            if (val) hrefs.push(val);
          }
          if (text.length < 3 && hrefs.length === 0) return;
          const key = `${sel}::${text.slice(0, 120)}::${hrefs.slice(0, 3).join("|")}`;
          if (seen.has(key)) return;
          seen.add(key);
          results.push({ text, hrefs });
        });
      }
      root.querySelectorAll?.("*")?.forEach((el) => {
        if (el.shadowRoot) walk(el.shadowRoot);
      });
    }

    walk(document);
    return results;
  }, selectors);
}

/** Walk full page shadow DOM for all links + body text. */
export async function harvestShadowLinks(page) {
  return page.evaluate(() => {
    const hrefs = new Set();

    function walk(root) {
      if (!root) return;
      root.querySelectorAll?.("a[href]")?.forEach((a) => {
        const href = a.getAttribute("href");
        if (href) hrefs.add(href);
      });
      root.querySelectorAll?.("*")?.forEach((el) => {
        if (el.shadowRoot) walk(el.shadowRoot);
      });
    }

    walk(document);
    document.querySelectorAll("shreddit-post, shreddit-comment, shreddit-ad-post").forEach((el) => {
      for (const attr of ["content-href", "permalink", "post-url", "href", "call-to-action-href"]) {
        const val = el.getAttribute(attr);
        if (val) hrefs.add(val);
      }
      if (el.shadowRoot) walk(el.shadowRoot);
    });

    // Link posts and previews often use target=_blank for outbound URLs
    document.querySelectorAll('a[target="_blank"][href^="http"]').forEach((a) => {
      hrefs.add(a.getAttribute("href"));
    });

    return { hrefs: [...hrefs], text: document.body?.innerText || "" };
  });
}

/**
 * Core scrape runner (SocialScraper-style).
 * @param {import('playwright').Page} page
 * @param {{ url: string, selectors: string[], maxScrolls?: number, expandComments?: boolean }} opts
 */
export async function runScrape(page, opts) {
  const { url, selectors, maxScrolls = 5, expandComments: doExpand = false } = opts;

  await page.goto(url, { waitUntil: "domcontentloaded", timeout: 60_000 });
  await page.waitForTimeout(2000);

  if (doExpand) await expandComments(page);
  await autoScroll(page, maxScrolls);

  const blocks = await extractSelectorBlocks(page, selectors);
  const shadow = await harvestShadowLinks(page);

  return { url, blocks, shadow };
}
