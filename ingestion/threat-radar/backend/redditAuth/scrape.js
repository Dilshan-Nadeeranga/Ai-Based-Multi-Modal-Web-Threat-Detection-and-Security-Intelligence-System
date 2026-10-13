import fs from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { launchRedditBrowser, redditUserAgent, autoScroll, extractSelectorBlocks, harvestShadowLinks } from "./baseScraper.js";
import { extractDomain, isExternalCandidate } from "./linkFilter.js";
import {
  buildSearchUrl,
  buildSubredditUrl,
  collectPostLinks,
  collectPostLinksOldReddit,
  discoverPostsFromRss,
  scrapeRedditPostDeep,
  waitForSearchResults,
  REDDIT_SELECTORS,
  urlsFromBlocks,
} from "./redditPlatform.js";
import { getSearchScope } from "./settings.js";
import { hasSession } from "./session.js";
import { readKeywords } from "../keywordsStore.js";

async function listingUrlsFromPage(page) {
  const blocks = await extractSelectorBlocks(page, REDDIT_SELECTORS);
  const shadow = await harvestShadowLinks(page);
  return urlsFromBlocks(blocks, shadow);
}

const backendRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const DATA_DIR = path.join(backendRoot, "data");
const SUBREDDITS_FILE = path.join(DATA_DIR, "reddit_subreddits.json");
const OUTPUT_CSV = path.join(DATA_DIR, "scraped", "reddit_urls_only.csv");

const MAX_POSTS_PER_SEARCH = Number(process.env.REDDIT_MAX_POSTS_PER_SEARCH) || 12;

async function readJson(file, fallback) {
  try {
    return JSON.parse(await fs.readFile(file, "utf-8"));
  } catch {
    return fallback;
  }
}

async function loadSubreddits() {
  const data = await readJson(SUBREDDITS_FILE, []);
  return Array.isArray(data) ? data.map((s) => String(s).replace(/^r\//, "").trim()).filter(Boolean) : [];
}

async function loadKeywords() {
  return readKeywords();
}

function subredditFromUrl(url) {
  try {
    const parts = new URL(url).pathname.split("/").filter(Boolean);
    if (parts[0] === "r") return parts[1] || "search";
    return parts[0] === "search" ? "search" : "";
  } catch {
    return "";
  }
}

function postIdFromUrl(url) {
  try {
    const parts = new URL(url).pathname.split("/").filter(Boolean);
    const idx = parts.indexOf("comments");
    return idx >= 0 && parts[idx + 1] ? parts[idx + 1] : "";
  } catch {
    return "";
  }
}

function makeRecord({ url, subreddit, postId, title, source }) {
  const domain = extractDomain(url);
  if (!domain || !isExternalCandidate(url)) return null;
  return {
    domain,
    url,
    subreddit,
    date: new Date().toISOString(),
    post_id: postId,
    score: "",
    title: `[${source}] ${title}`.slice(0, 200),
  };
}

function recordsFromUrls(urls, meta) {
  const records = [];
  const seenDomains = new Set();

  for (const url of urls) {
    const domain = extractDomain(url);
    if (!domain || seenDomains.has(domain)) continue;
    const record = makeRecord({
      url,
      subreddit: meta.subreddit,
      postId: meta.postId,
      title: meta.title || domain,
      source: meta.source,
    });
    if (!record) continue;
    seenDomains.add(domain);
    records.push(record);
  }
  return records;
}

async function appendCsv(records) {
  if (!records.length) return 0;

  let existingDomains = new Set();
  try {
    const raw = await fs.readFile(OUTPUT_CSV, "utf-8");
    const headerLine = raw.split("\n")[0] ?? "";
    const hasDomainCol = headerLine.startsWith("domain,");
    for (const line of raw.split("\n").slice(1)) {
      if (!line.trim()) continue;
      const cols = line.split(",");
      const domain = hasDomainCol ? cols[0] : extractDomain(cols[0]);
      if (domain) existingDomains.add(domain);
    }
  } catch { /* new file */ }

  const fresh = records.filter((r) => r?.domain && !existingDomains.has(r.domain));
  if (!fresh.length) return 0;

  await fs.mkdir(path.dirname(OUTPUT_CSV), { recursive: true });

  const header = "domain,url,subreddit,date,post_id,score,title\n";
  const lines = fresh.map((r) =>
    [r.domain, r.url, r.subreddit, r.date, r.post_id, r.score, `"${r.title.replace(/"/g, '""')}"`].join(",")
  ).join("\n") + "\n";

  let exists = false;
  try {
    await fs.access(OUTPUT_CSV);
    exists = true;
  } catch { /* new file */ }

  if (!exists) {
    await fs.writeFile(OUTPUT_CSV, header + lines);
  } else {
    await fs.appendFile(OUTPUT_CSV, lines);
  }
  console.log(`[reddit-browser] Saved ${fresh.length} new domain(s) → ${OUTPUT_CSV}`);
  return fresh.length;
}

async function scrapePostWithComments(page, postUrl, keyword) {
  const urls = await scrapeRedditPostDeep(page, postUrl);
  const records = recordsFromUrls(urls, {
    subreddit: subredditFromUrl(postUrl),
    postId: postIdFromUrl(postUrl),
    title: keyword,
    source: "found",
  });

  if (records.length) {
    await appendCsv(records);
  }

  const names = records.map((r) => r.domain).join(", ") || "none";
  console.log(`[reddit-browser] ${postUrl} → ${records.length} domain(s) [${keyword}]: ${names}`);

  return records;
}

async function scrapeGlobalKeywordOnPage(page, keyword) {
  const searchUrl = buildSearchUrl(keyword, "posts");
  console.log(`[reddit-browser] Global search: "${keyword}"`);

  await page.goto(searchUrl, { waitUntil: "domcontentloaded", timeout: 60_000 });
  if (await waitForSearchResults(page)) await page.waitForTimeout(1500);
  await autoScroll(page, 5);

  const listingUrls = await listingUrlsFromPage(page);
  const listingRecords = recordsFromUrls(listingUrls, {
    subreddit: "search",
    postId: "",
    title: keyword,
    source: "listing",
  });
  const records = [...listingRecords];
  if (listingRecords.length) await appendCsv(listingRecords);

  let postLinks = await collectPostLinks(page);

  if (!postLinks.length) {
    console.log(`[reddit-browser] New Reddit search empty — trying old.reddit.com...`);
    postLinks = await collectPostLinksOldReddit(page, keyword);
  }
  if (!postLinks.length) {
    console.log(`[reddit-browser] Trying RSS post discovery...`);
    postLinks = await discoverPostsFromRss(keyword, redditUserAgent());
  }

  console.log(
    `[reddit-browser] search:"${keyword}" found ${postLinks.length} post(s), deep-scraping ${Math.min(postLinks.length, MAX_POSTS_PER_SEARCH)}`
  );

  for (const postUrl of postLinks.slice(0, MAX_POSTS_PER_SEARCH)) {
    try {
      records.push(...await scrapePostWithComments(page, postUrl, keyword));
    } catch (err) {
      console.error(`[reddit-browser] Post scrape failed (${postUrl}): ${err.message}`);
    }
  }

  const commentSearchUrl = buildSearchUrl(keyword, "comment");
  try {
    await page.goto(commentSearchUrl, { waitUntil: "domcontentloaded", timeout: 60_000 });
    await waitForSearchResults(page);
    await autoScroll(page, 3);
    const commentLinks = (await collectPostLinks(page)).slice(0, MAX_POSTS_PER_SEARCH);
    console.log(`[reddit-browser] comment search:"${keyword}" found ${commentLinks.length} thread(s)`);
    for (const postUrl of commentLinks) {
      try {
        records.push(...await scrapePostWithComments(page, postUrl, keyword));
      } catch (err) {
        console.error(`[reddit-browser] Comment-thread scrape failed (${postUrl}): ${err.message}`);
      }
    }
  } catch (err) {
    console.error(`[reddit-browser] Comment search failed: ${err.message}`);
  }

  return records;
}

async function scrapeSubredditOnPage(page, subreddit, keywords) {
  const url = buildSubredditUrl(subreddit);
  await page.goto(url, { waitUntil: "domcontentloaded", timeout: 60_000 });
  await page.waitForTimeout(2000);
  await autoScroll(page, 4);

  const listingUrls = await listingUrlsFromPage(page);
  const listingRecords = recordsFromUrls(listingUrls, {
    subreddit,
    postId: "",
    title: keywords.join("|") || "all",
    source: "listing",
  });
  const records = [...listingRecords];
  if (listingRecords.length) await appendCsv(listingRecords);

  const postLinks = await collectPostLinks(page);
  for (const postUrl of postLinks.slice(0, MAX_POSTS_PER_SEARCH)) {
    try {
      records.push(...await scrapePostWithComments(page, postUrl, keywords.join("|") || "all"));
    } catch (err) {
      console.error(`[reddit-browser] Post scrape failed (${postUrl}): ${err.message}`);
    }
  }

  return records;
}

/** Run one manual scrape (keyword and/or direct Reddit URL). */
export async function runManualScrape({ keyword, url } = {}) {
  if (!hasSession()) {
    throw new Error("No Reddit session. Import cookies or log in via the website.");
  }

  const { browser, page } = await launchRedditBrowser();
  let records = [];

  try {
    if (url) {
      const urls = await scrapeRedditPostDeep(page, url);
      records = recordsFromUrls(urls, {
        subreddit: subredditFromUrl(url),
        postId: postIdFromUrl(url),
        title: keyword || url,
        source: "manual",
      });
    } else if (keyword) {
      records = await scrapeGlobalKeywordOnPage(page, keyword);
    } else {
      throw new Error("Provide keyword or url");
    }

    const saved = await appendCsv(records);
    return { found: records.length, saved, domains: [...new Set(records.map((r) => r.domain))] };
  } finally {
    await browser.close();
  }
}

export async function runWatchCycle() {
  if (!hasSession()) {
    throw new Error("No Reddit session. Log in via the website first.");
  }

  const searchScope = getSearchScope();
  const subreddits = await loadSubreddits();
  const keywords = await loadKeywords();
  let total = 0;

  const needsGlobal = searchScope === "global" || searchScope === "both";
  const needsSubs = searchScope === "subreddits" || searchScope === "both";

  if (needsGlobal && !keywords.length) {
    console.log("[reddit-browser] Global search needs at least one keyword");
  }
  if (needsSubs && !subreddits.length) {
    console.log("[reddit-browser] Subreddit mode needs at least one subreddit");
  }
  if ((needsGlobal && !keywords.length) && (needsSubs && !subreddits.length)) {
    return 0;
  }

  const { browser, page } = await launchRedditBrowser();

  try {
    if (needsGlobal && keywords.length) {
      console.log(`[reddit-browser] Mode: global search · ${keywords.length} keyword(s)`);
      for (const kw of keywords) {
        try {
          const records = await scrapeGlobalKeywordOnPage(page, kw);
          total += records.length;
          console.log(`[reddit-browser] search:"${kw}" → ${records.length} domain(s) found this cycle`);
        } catch (err) {
          console.error(`[reddit-browser] search:"${kw}": ${err.message}`);
        }
      }
    }

    if (needsSubs && subreddits.length) {
      console.log(`[reddit-browser] Mode: subreddits · ${subreddits.length} sub(s)`);
      for (const sub of subreddits) {
        try {
          const records = await scrapeSubredditOnPage(page, sub, keywords);
          total += records.length;
          console.log(`[reddit-browser] r/${sub}: ${records.length} domain(s)`);
        } catch (err) {
          console.error(`[reddit-browser] r/${sub}: ${err.message}`);
        }
      }
    }
  } finally {
    await browser.close();
  }

  return total;
}
