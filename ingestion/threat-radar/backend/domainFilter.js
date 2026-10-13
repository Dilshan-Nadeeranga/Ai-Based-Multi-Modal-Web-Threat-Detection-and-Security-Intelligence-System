/**
 * Filter domains-monitor downloaded lists by suspicious keywords + brand mimicry.
 * Output: backend/data/filtered/filtered_domains_YYYY-MM-DD.json
 */

import { createReadStream } from "fs";
import fs from "fs/promises";
import path from "path";
import readline from "readline";
import { fileURLToPath } from "url";
import { config } from "./config.js";
import { todayStamp } from "./downloadJob.js";

const backendRoot = path.dirname(fileURLToPath(import.meta.url));

export const DOMAIN_KEYWORDS_FILE = path.join(
  backendRoot,
  "data",
  "domain_keywords.json"
);
export const FILTERED_DIR = path.join(backendRoot, "data", "filtered");

/** Brands commonly targeted by typosquatting / homoglyph attacks */
const DEFAULT_BRANDS = [
  "google", "gmail", "youtube",
  "microsoft", "windows", "office", "outlook", "azure",
  "apple", "icloud",
  "amazon", "aws",
  "facebook", "meta", "instagram", "whatsapp",
  "paypal", "stripe",
  "netflix", "spotify",
  "binance", "coinbase", "kraken", "kucoin", "bybit", "okx", "metamask",
  "chase", "wellsfargo", "bankofamerica", "citibank",
  "telegram", "discord",
  "dropbox", "docusign",
  "linkedin", "twitter",
];

const EXTRA_BRANDS = (process.env.DOMAIN_FILTER_BRANDS ?? "")
  .split(",")
  .map((b) => b.trim().toLowerCase())
  .filter(Boolean);

const BRANDS = [...new Set([...DEFAULT_BRANDS, ...EXTRA_BRANDS])];

const HOMOGLYPH_MAP = {
  "0": "o",
  "1": "l",
  "3": "e",
  "4": "a",
  "5": "s",
  "@": "a",
  $: "s",
  "!": "i",
};

export async function loadDomainKeywords() {
  try {
    const raw = await fs.readFile(DOMAIN_KEYWORDS_FILE, "utf-8");
    const data = JSON.parse(raw);
    return Array.isArray(data)
      ? data.map((k) => String(k).trim().toLowerCase()).filter(Boolean)
      : [];
  } catch {
    return [];
  }
}

export async function saveDomainKeywords(keywords) {
  await fs.mkdir(path.dirname(DOMAIN_KEYWORDS_FILE), { recursive: true });
  const list = keywords
    .map((k) => String(k).trim().toLowerCase())
    .filter(Boolean);
  await fs.writeFile(
    DOMAIN_KEYWORDS_FILE,
    JSON.stringify([...new Set(list)], null, 2),
    "utf-8"
  );
  return list;
}

function extractSld(domain) {
  const d = domain.toLowerCase().trim().replace(/^www\./, "");
  const parts = d.split(".").filter(Boolean);
  if (parts.length < 2) return parts[0] ?? d;
  return parts[0];
}

function normalizeMimicry(text) {
  let s = text.toLowerCase();
  s = s.replace(/rn/g, "m");
  s = s.replace(/vv/g, "w");
  s = s.replace(/cl/g, "d");
  return [...s].map((c) => HOMOGLYPH_MAP[c] ?? c).join("");
}

function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
    }
  }
  return dp[m][n];
}

/**
 * Detect brand mimicry (g00gle.com, rnicrosoft.com, paypal-secure.xyz).
 * @returns {{ brand: string, type: string } | null}
 */
export function detectBrandMimicry(domain) {
  const sld = extractSld(domain);
  if (!sld || sld.length < 4) return null;

  const normalized = normalizeMimicry(sld);

  for (const brand of BRANDS) {
    if (sld === brand) continue;

    if (normalized === brand && sld !== brand) {
      return { brand, type: "homoglyph" };
    }

    if (sld.includes(brand) && sld !== brand) {
      return { brand, type: "contains_brand" };
    }

    const dist = levenshtein(normalized, brand);
    if (dist > 0 && dist <= 2 && Math.abs(normalized.length - brand.length) <= 2) {
      return { brand, type: "typosquat" };
    }
  }

  return null;
}

function matchKeywords(domain, keywords) {
  const matched = keywords.filter((kw) => domain.includes(kw));
  return matched;
}

async function* readDomainLines(filePath) {
  const rl = readline.createInterface({
    input: createReadStream(filePath, { encoding: "utf-8" }),
    crlfDelay: Infinity,
  });
  for await (const line of rl) {
    const domain = line.trim().toLowerCase();
    if (domain && !domain.startsWith("#")) yield domain;
  }
}

/**
 * Filter a downloaded .txt domain list and save JSON results.
 */
export async function filterDomainsFromFile(sourcePath, opts = {}) {
  const keywords = opts.keywords ?? (await loadDomainKeywords());
  const outName =
    opts.outputName ?? `filtered_domains_${todayStamp()}.json`;
  const outPath = path.join(FILTERED_DIR, outName);

  await fs.mkdir(FILTERED_DIR, { recursive: true });

  const matches = [];
  let totalScanned = 0;

  for await (const domain of readDomainLines(sourcePath)) {
    totalScanned++;
    const matchedKeywords = matchKeywords(domain, keywords);
    const mimic = detectBrandMimicry(domain);
    const reasons = [];

    if (matchedKeywords.length) reasons.push("keyword");
    if (mimic) reasons.push(`brand_mimicry:${mimic.brand}`);

    if (!reasons.length) continue;

    matches.push({
      domain,
      reasons,
      matchedKeywords,
      ...(mimic ? { mimicBrand: mimic.brand, mimicType: mimic.type } : {}),
    });
  }

  const payload = {
    sourceFile: path.basename(sourcePath),
    filteredAt: new Date().toISOString(),
    totalScanned,
    matchedCount: matches.length,
    keywordCount: keywords.length,
    brandsChecked: BRANDS.length,
    domains: matches,
  };

  await fs.writeFile(outPath, JSON.stringify(payload, null, 2), "utf-8");

  console.log(
    `[domain-filter] ${matches.length} suspicious of ${totalScanned.toLocaleString()} ` +
      `→ ${outPath}`
  );

  return {
    saved: outName,
    path: outPath,
    totalScanned,
    matchedCount: matches.length,
    ...payload,
  };
}

/** Filter the newest .txt file in the download directory. */
export async function filterLatestDownload() {
  const files = await fs.readdir(config.downloadDir).catch(() => []);
  const txtFiles = files.filter((f) => f.endsWith(".txt"));
  if (!txtFiles.length) {
    throw new Error("No .txt domain list found in downloads folder");
  }

  const stats = await Promise.all(
    txtFiles.map(async (name) => {
      const p = path.join(config.downloadDir, name);
      const s = await fs.stat(p);
      return { name, path: p, mtime: s.mtimeMs };
    })
  );
  stats.sort((a, b) => b.mtime - a.mtime);
  return filterDomainsFromFile(stats[0].path);
}

export async function listFilteredResults() {
  await fs.mkdir(FILTERED_DIR, { recursive: true });
  const files = await fs.readdir(FILTERED_DIR);
  const jsonFiles = files.filter((f) => f.endsWith(".json"));
  const stats = await Promise.all(
    jsonFiles.map(async (name) => {
      const p = path.join(FILTERED_DIR, name);
      const s = await fs.stat(p);
      return { name, bytes: s.size, modified: s.mtime.toISOString() };
    })
  );
  return stats.sort((a, b) => b.modified.localeCompare(a.modified));
}

export async function readFilteredJson(filename) {
  const safe = path.basename(filename);
  const p = path.join(FILTERED_DIR, safe);
  const raw = await fs.readFile(p, "utf-8");
  return JSON.parse(raw);
}
