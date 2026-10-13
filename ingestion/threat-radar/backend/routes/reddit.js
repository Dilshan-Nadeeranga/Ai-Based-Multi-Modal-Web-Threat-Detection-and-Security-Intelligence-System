import { Router } from "express";
import fs from "fs/promises";
import path from "path";
import { config } from "../config.js";
import { extractDomain, isExternalCandidate } from "../redditAuth/linkFilter.js";
import {
  getRedditSettings,
  updateRedditSettings,
} from "../redditAuth/settings.js";
import {
  isRedditScraperRunning,
  startRedditScraper,
  stopRedditScraper,
} from "../redditScraperProcess.js";
import { runManualScrape } from "../redditAuth/scrape.js";
import { queryStoredPosts } from "../db.js";

export const redditRouter = Router();

const SCRAPED_DIR = path.join(config.downloadDir, "..", "scraped");
const REDDIT_URLS_FILE = path.join(SCRAPED_DIR, "reddit_urls_only.csv");
const REDDIT_POSTS_FILE = path.join(SCRAPED_DIR, "reddit_posts.csv");
const REDDIT_IMAGES_DIR = path.join(SCRAPED_DIR, "reddit_images");
const SUBREDDITS_FILE = path.join(config.downloadDir, "..", "reddit_subreddits.json");

async function readSubreddits() {
  try {
    const raw = await fs.readFile(SUBREDDITS_FILE, "utf-8");
    const data = JSON.parse(raw);
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}

async function writeSubreddits(subreddits) {
  await fs.mkdir(path.dirname(SUBREDDITS_FILE), { recursive: true });
  await fs.writeFile(SUBREDDITS_FILE, JSON.stringify(subreddits, null, 2), "utf-8");
}

function normalizeSubreddit(name) {
  return String(name ?? "").trim().replace(/^r\//i, "").replace(/\//g, "");
}

function parseCsvLine(line) {
  const values = [];
  let cur = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') {
      if (inQuotes && line[i + 1] === '"') {
        cur += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }
    if (c === "," && !inQuotes) {
      values.push(cur);
      cur = "";
      continue;
    }
    cur += c;
  }
  values.push(cur);
  return values;
}

/** Parse the Reddit CSV into JSON rows. */
async function readRedditUrls(limit = 500) {
  try {
    const raw = await fs.readFile(REDDIT_URLS_FILE, "utf-8");
    const lines = raw.split("\n").filter(Boolean);
    if (lines.length < 2) return [];

    const headers = parseCsvLine(lines[0]);
    const rows = lines
      .slice(1)
      .slice(0, limit)
      .map((line) => {
        const values = parseCsvLine(line);
        return Object.fromEntries(headers.map((h, i) => [h, values[i] ?? ""]));
      })
      .map((row) => ({
        ...row,
        domain: row.domain || extractDomain(row.url || ""),
        url: row.url || "",
      }))
      .filter((row) => row.domain && isExternalCandidate(row.url || `https://${row.domain}`));

    const seen = new Set();
    return rows.filter((row) => {
      if (seen.has(row.domain)) return false;
      seen.add(row.domain);
      return true;
    });
  } catch {
    return [];
  }
}

/** GET /api/reddit/stored — posts saved in PostgreSQL */
redditRouter.get("/stored", async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit ?? 100) || 100, 1), 200);
  try {
    const data = await queryStoredPosts(limit);
    if (!data.configured) {
      return res.status(503).json({ error: "Database is not configured", count: 0, results: [] });
    }
    res.json({ count: data.posts.length, results: data.posts });
  } catch (err) {
    console.error("[stored] read failed:", err instanceof Error ? err.message : "unknown error");
    res.status(500).json({ error: "Could not read stored posts", count: 0, results: [] });
  }
});

/** GET /api/reddit/posts — keyword posts with text, image files, and URLs */
redditRouter.get("/posts", async (req, res) => {
  const limit = Math.min(Number(req.query.limit ?? 100), 500);
  try {
    const raw = await fs.readFile(REDDIT_POSTS_FILE, "utf-8");
    const lines = raw.split("\n").filter(Boolean);
    if (lines.length < 2) return res.json({ count: 0, results: [] });
    const headers = parseCsvLine(lines[0]);
    const results = lines.slice(1).slice(-limit).reverse().map((line) => {
      const values = parseCsvLine(line);
      const row = Object.fromEntries(headers.map((h, i) => [h, values[i] ?? ""]));
      row.image_files = String(row.image_files || "").split(/\s+/).filter(Boolean);
      row.image_urls = String(row.image_urls || "").split(/\s+/).filter(Boolean);
      row.urls = String(row.urls || "").split(/\s+/).filter(Boolean);
      return row;
    });
    res.json({ count: results.length, results });
  } catch {
    res.json({ count: 0, results: [] });
  }
});

/** GET /api/reddit/images/:name — a downloaded post image */
redditRouter.get("/images/:name", async (req, res) => {
  const name = path.basename(req.params.name);
  if (!/^[\w.-]+$/.test(name)) return res.status(400).json({ error: "bad image name" });
  const file = path.join(REDDIT_IMAGES_DIR, name);
  try {
    const data = await fs.readFile(file);
    const ext = path.extname(name).toLowerCase();
    const type = { ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".gif": "image/gif", ".webp": "image/webp" }[ext] || "application/octet-stream";
    res.setHeader("Content-Type", type);
    res.send(data);
  } catch {
    res.status(404).json({ error: "image not found" });
  }
});

/** GET /api/reddit/results */
redditRouter.get("/results", async (req, res) => {
  const limit = Math.min(Number(req.query.limit ?? 200), 1000);
  try {
    const rows = await readRedditUrls(limit);
    const stat = await fs.stat(REDDIT_URLS_FILE).catch(() => null);
    res.json({
      count: rows.length,
      lastModified: stat?.mtime?.toISOString() ?? null,
      results: rows,
    });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

/** DELETE /api/reddit/results */
redditRouter.delete("/results", async (_req, res) => {
  try {
    await fs.rm(REDDIT_URLS_FILE, { force: true });
    await fs.rm(path.join(SCRAPED_DIR, "reddit_scraped_urls.csv"), { force: true });
    await fs.rm(REDDIT_POSTS_FILE, { force: true });
    await fs.rm(path.join(SCRAPED_DIR, "reddit_posts.jsonl"), { force: true });
    await fs.rm(REDDIT_IMAGES_DIR, { recursive: true, force: true });
    res.json({ cleared: true });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

/** GET /api/reddit/status */
redditRouter.get("/status", async (_req, res) => {
  try {
    const stat = await fs.stat(REDDIT_URLS_FILE).catch(() => null);
    res.json({
      hasResults: stat !== null,
      lastModified: stat?.mtime?.toISOString() ?? null,
      outputFile: REDDIT_URLS_FILE,
    });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

/** GET /api/reddit/subreddits */
redditRouter.get("/subreddits", async (_req, res) => {
  res.json({ subreddits: await readSubreddits() });
});

/** POST /api/reddit/subreddits */
redditRouter.post("/subreddits", async (req, res) => {
  const subreddit = normalizeSubreddit(req.body?.subreddit);
  if (!subreddit) return res.status(400).json({ error: "subreddit is required" });

  const subreddits = await readSubreddits();
  if (subreddits.map((s) => s.toLowerCase()).includes(subreddit.toLowerCase())) {
    return res.status(409).json({ error: "Subreddit already exists" });
  }
  subreddits.push(subreddit);
  await writeSubreddits(subreddits);
  res.json({ subreddits });
});

/** DELETE /api/reddit/subreddits/:subreddit */
redditRouter.delete("/subreddits/:subreddit", async (req, res) => {
  const subreddit = normalizeSubreddit(decodeURIComponent(req.params.subreddit));
  const subreddits = (await readSubreddits()).filter(
    (s) => s.toLowerCase() !== subreddit.toLowerCase()
  );
  await writeSubreddits(subreddits);
  res.json({ subreddits });
});

/** POST /api/reddit/scrape-now  { keyword?, url? } — one-off scrape like SocialScraper */
redditRouter.post("/scrape-now", async (req, res) => {
  const { keyword, url } = req.body ?? {};
  if (!keyword && !url) {
    return res.status(400).json({ error: "Provide keyword or url" });
  }
  try {
    const result = await runManualScrape({ keyword, url });
    res.json({ ok: true, ...result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** GET /api/reddit/settings */
redditRouter.get("/settings", async (_req, res) => {
  const settings = getRedditSettings();
  res.json({
    autoScrape: settings.autoScrape,
    searchScope: settings.searchScope ?? "global",
    pollIntervalSeconds: settings.pollIntervalSeconds ?? 300,
    running: isRedditScraperRunning(),
  });
});

/** PUT /api/reddit/settings  { autoScrape?, searchScope?, pollIntervalSeconds? } */
redditRouter.put("/settings", async (req, res) => {
  const { autoScrape, searchScope, pollIntervalSeconds } = req.body ?? {};

  if (autoScrape !== undefined && typeof autoScrape !== "boolean") {
    return res.status(400).json({ error: "autoScrape must be a boolean" });
  }
  if (searchScope !== undefined && !["global", "subreddits", "both"].includes(searchScope)) {
    return res.status(400).json({ error: "searchScope must be global, subreddits, or both" });
  }
  if (pollIntervalSeconds !== undefined && Number.isNaN(Number(pollIntervalSeconds))) {
    return res.status(400).json({ error: "pollIntervalSeconds must be a number" });
  }

  try {
    const partial = {};
    if (autoScrape !== undefined) partial.autoScrape = autoScrape;
    if (searchScope !== undefined) partial.searchScope = searchScope;
    if (pollIntervalSeconds !== undefined) partial.pollIntervalSeconds = Number(pollIntervalSeconds);

    const settings = Object.keys(partial).length
      ? updateRedditSettings(partial)
      : getRedditSettings();

    if (autoScrape === true) startRedditScraper();
    if (autoScrape === false) stopRedditScraper();

    res.json({
      autoScrape: settings.autoScrape,
      searchScope: settings.searchScope ?? "global",
      pollIntervalSeconds: settings.pollIntervalSeconds ?? 300,
      running: isRedditScraperRunning(),
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});
