import {
  autoScroll,
  expandComments,
  extractSelectorBlocks,
  harvestShadowLinks,
  runScrape,
} from "./baseScraper.js";
import { extractUrls, filterUrls, isExternalCandidate } from "./linkFilter.js";

/** Broad selectors — same style as SocialScraper reddit.js */
export const REDDIT_SELECTORS = [
  "shreddit-post",
  '[data-testid="post-container"]',
  'div[data-testid="post-content"]',
  'a[data-click-id="body"]',
  "p.title",
  "div.md",
  '[data-adclicklocation="title"]',
  'div[data-testid="post-content-header"]',
  "h3",
  'a[href*="/comments/"]',
  'div[slot="post-body"]',
  "faceplate-tracker",
  "shreddit-comment",
  '[data-testid="comment"]',
];

function normalizeHref(href) {
  if (!href || href.startsWith("#") || href.startsWith("javascript:")) return null;
  if (href.startsWith("/")) return `https://www.reddit.com${href}`;
  return href;
}

export function urlsFromBlocks(blocks, shadow) {
  const urls = new Set();

  for (const block of blocks) {
    for (const u of extractUrls(block.text)) urls.add(u);
    for (const href of block.hrefs ?? []) {
      const full = normalizeHref(href);
      if (full && isExternalCandidate(full)) urls.add(full);
    }
  }

  for (const u of extractUrls(shadow?.text || "")) urls.add(u);
  for (const href of shadow?.hrefs ?? []) {
    const full = normalizeHref(href);
    if (full && isExternalCandidate(full)) urls.add(full);
  }

  return filterUrls([...urls]);
}

/**
 * Scrape a Reddit URL (subreddit, search, or post) and return external URLs only.
 * @param {import('playwright').Page} page
 * @param {string} targetUrl
 * @param {{ maxScrolls?: number, expandComments?: boolean }} options
 */
export async function scrapeRedditUrl(page, targetUrl, options = {}) {
  const { blocks, shadow } = await runScrape(page, {
    url: targetUrl,
    selectors: REDDIT_SELECTORS,
    maxScrolls: options.maxScrolls ?? 6,
    expandComments: options.expandComments ?? targetUrl.includes("/comments/"),
  });

  return urlsFromBlocks(blocks, shadow);
}

export async function scrapeRedditPostDeep(page, postUrl, options = {}) {
  let urls = await scrapeRedditUrl(page, postUrl, {
    maxScrolls: options.maxScrolls ?? 8,
    expandComments: true,
  });

  if (!urls.length) {
    urls = await scrapeOldRedditPost(page, postUrl);
  }

  return urls;
}

/** old.reddit.com exposes plain HTML links — reliable fallback when new Reddit hides them in shadow DOM. */
export async function scrapeOldRedditPost(page, postUrl) {
  const oldUrl = postUrl.replace("://www.reddit.com", "://old.reddit.com");
  try {
    await page.goto(oldUrl, { waitUntil: "domcontentloaded", timeout: 60_000 });
    await page.waitForTimeout(2000);
    await autoScroll(page, 4);

    const data = await page.evaluate(() => {
      const hrefs = [...document.querySelectorAll("a[href]")]
        .map((a) => a.href)
        .filter(Boolean);
      return { hrefs, text: document.body?.innerText || "" };
    });

    const urls = new Set(extractUrls(data.text));
    for (const href of data.hrefs) {
      const full = normalizeHref(href);
      if (full && isExternalCandidate(full)) urls.add(full);
    }
    return filterUrls([...urls]);
  } catch {
    return [];
  }
}

export function buildSearchUrl(keyword, type = "posts") {
  return `https://www.reddit.com/search/?q=${encodeURIComponent(keyword)}&sort=new&type=${type}`;
}

export function buildSubredditUrl(subreddit) {
  return `https://www.reddit.com/r/${subreddit}/new/`;
}

export async function collectPostLinks(page) {
  const blocks = await extractSelectorBlocks(page, REDDIT_SELECTORS);
  const shadow = await harvestShadowLinks(page);
  const links = new Set();

  const addPost = (href) => {
    const full = normalizeHref(href);
    if (!full?.includes("/comments/")) return;
    try {
      const u = new URL(full.startsWith("http") ? full : `https://www.reddit.com${full}`);
      links.add(`${u.origin}${u.pathname}`.replace(/\/$/, ""));
    } catch { /* skip */ }
  };

  for (const block of blocks) {
    for (const href of block.hrefs ?? []) addPost(href);
  }
  for (const href of shadow?.hrefs ?? []) addPost(href);

  return [...links];
}

export async function collectPostLinksOldReddit(page, keyword) {
  const url = `https://old.reddit.com/search?q=${encodeURIComponent(keyword)}&sort=new&t=week`;
  await page.goto(url, { waitUntil: "domcontentloaded", timeout: 60_000 });
  await page.waitForTimeout(2500);
  await autoScroll(page, 3);

  const blocks = await extractSelectorBlocks(page, ['a[href*="/comments/"]', "a.title"]);
  const links = new Set();

  for (const block of blocks) {
    for (const href of block.hrefs ?? []) {
      if (!href.includes("/comments/")) continue;
      try {
        const u = new URL(href.startsWith("http") ? href : `https://old.reddit.com${href}`);
        links.add(`https://www.reddit.com${u.pathname}`.replace(/\/$/, ""));
      } catch { /* skip */ }
    }
  }
  return [...links];
}

export async function waitForSearchResults(page) {
  const selectors = [
    'a[href*="/comments/"]',
    "shreddit-post",
    '[data-testid="sdui-post-unit"]',
  ].join(", ");

  try {
    await page.waitForSelector(selectors, { timeout: 20_000 });
    return true;
  } catch {
    return false;
  }
}

export async function discoverPostsFromRss(keyword, userAgent) {
  const url = `https://www.reddit.com/search.rss?q=${encodeURIComponent(keyword)}&sort=new`;
  try {
    const resp = await fetch(url, { headers: { "User-Agent": userAgent } });
    if (!resp.ok) return [];

    const xml = await resp.text();
    if (!xml.includes("<entry")) return [];

    const links = [];
    const seen = new Set();
    for (const match of xml.matchAll(/<link[^>]+href="([^"]+)"/g)) {
      const href = match[1];
      if (!href.includes("/comments/") || seen.has(href)) continue;
      seen.add(href);
      try {
        const u = new URL(href);
        links.push(`${u.origin}${u.pathname}`.replace(/\/$/, ""));
      } catch { /* skip */ }
    }
    return links;
  } catch {
    return [];
  }
}
