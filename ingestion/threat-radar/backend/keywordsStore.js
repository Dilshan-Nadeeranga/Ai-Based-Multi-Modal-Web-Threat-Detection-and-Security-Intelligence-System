import fs from "fs/promises";
import path from "path";
import { config } from "./config.js";

const KEYWORDS_FILE = path.join(config.downloadDir, "..", "keywords.json");

/** Comma-separated keywords for cloud deploy (Render resets data/ on redeploy). */
export function keywordsFromEnv() {
  const raw =
    process.env.SCAM_KEYWORDS ??
    process.env.REDDIT_KEYWORDS ??
    process.env.TELEGRAM_KEYWORDS ??
    "";
  if (!raw.trim()) return [];
  return raw
    .split(",")
    .map((k) => k.trim().toLowerCase())
    .filter(Boolean);
}

export async function readKeywords() {
  try {
    const raw = await fs.readFile(KEYWORDS_FILE, "utf-8");
    const data = JSON.parse(raw);
    const list = Array.isArray(data)
      ? data.map((k) => String(k).trim().toLowerCase()).filter(Boolean)
      : [];
    if (list.length) return list;
  } catch {
    /* no file yet */
  }
  return keywordsFromEnv();
}

export async function writeKeywords(keywords) {
  await fs.mkdir(path.dirname(KEYWORDS_FILE), { recursive: true });
  await fs.writeFile(KEYWORDS_FILE, JSON.stringify(keywords, null, 2), "utf-8");
  return keywords;
}

/** Seed keywords.json from env when empty (survives Render redeploy via env var). */
export async function seedKeywordsFromEnv() {
  const existing = await readKeywords();
  if (existing.length) return existing;
  const fromEnv = keywordsFromEnv();
  if (!fromEnv.length) return [];
  console.log(`[keywords] Seeding ${fromEnv.length} keyword(s) from env`);
  return writeKeywords(fromEnv);
}
