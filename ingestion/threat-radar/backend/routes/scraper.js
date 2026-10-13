import { Router } from "express";
import fs from "fs/promises";
import path from "path";
import { config } from "../config.js";
import { runBatchOnce } from "../scraperProcess.js";

export const scraperRouter = Router();

const SCRAPED_DIR = path.join(config.downloadDir, "..", "scraped");
const URLS_ONLY_FILE = path.join(SCRAPED_DIR, "urls_only.csv");
const SEEN_DOMAINS_FILE = path.join(SCRAPED_DIR, "seen_domains.json");

function todayUtc() {
  return new Date().toISOString().slice(0, 10);
}

/** Parse CSV rows (simple — URLs should not contain unquoted commas). */
async function readScrapedUrls(limit = 500, todayOnly = true) {
  try {
    const raw = await fs.readFile(URLS_ONLY_FILE, "utf-8");
    const lines = raw.split("\n").filter(Boolean);
    if (lines.length < 2) return [];

    const headers = lines[0].split(",");
    const rows = lines.slice(1).map((line) => {
      const values = line.split(",");
      return Object.fromEntries(headers.map((h, i) => [h, values[i] ?? ""]));
    });

    const filtered = todayOnly
      ? rows.filter((r) => (r.date ?? "").slice(0, 10) === todayUtc())
      : rows;

    return filtered.slice(0, limit);
  } catch {
    return [];
  }
}

/** GET /api/scraper/results */
scraperRouter.get("/results", async (req, res) => {
  const limit = Math.min(Number(req.query.limit ?? 200), 1000);
  const todayOnly = req.query.today !== "false";
  try {
    const rows = await readScrapedUrls(limit, todayOnly);
    const stat = await fs.stat(URLS_ONLY_FILE).catch(() => null);
    let seenCount = 0;
    try {
      const seen = JSON.parse(await fs.readFile(SEEN_DOMAINS_FILE, "utf-8"));
      seenCount = Object.keys(seen).length;
    } catch {
      /* no seen file yet */
    }
    res.json({
      count: rows.length,
      today: todayUtc(),
      todayOnly,
      seenDomainsTotal: seenCount,
      lastModified: stat?.mtime?.toISOString() ?? null,
      results: rows,
    });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

/** DELETE /api/scraper/results — clear today's output; ?all=true also clears seen domains */
scraperRouter.delete("/results", async (req, res) => {
  try {
    await fs.rm(URLS_ONLY_FILE, { force: true });
    await fs.rm(path.join(SCRAPED_DIR, "scraped_urls.csv"), { force: true });
    await fs.rm(path.join(SCRAPED_DIR, "urls_only_date.txt"), { force: true });
    if (req.query.all === "true") {
      await fs.rm(SEEN_DOMAINS_FILE, { force: true });
    }
    res.json({ cleared: true, seenCleared: req.query.all === "true" });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

/** POST /api/scraper/run — trigger batch scrape now */
scraperRouter.post("/run", async (_req, res) => {
  const result = await runBatchOnce();
  if (!result.ok) {
    return res.status(400).json({ error: result.reason ?? "Could not start scraper" });
  }
  res.json({ started: true, message: "Batch scrape started" });
});

/** GET /api/scraper/status */
scraperRouter.get("/status", async (_req, res) => {
  try {
    const stat = await fs.stat(URLS_ONLY_FILE).catch(() => null);
    let seenCount = 0;
    try {
      const seen = JSON.parse(await fs.readFile(SEEN_DOMAINS_FILE, "utf-8"));
      seenCount = Object.keys(seen).length;
    } catch {
      /* ignore */
    }
    res.json({
      hasResults: stat !== null,
      today: todayUtc(),
      seenDomainsTotal: seenCount,
      lastModified: stat?.mtime?.toISOString() ?? null,
      outputFile: URLS_ONLY_FILE,
    });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});
