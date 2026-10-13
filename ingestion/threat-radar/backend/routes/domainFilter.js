import { Router } from "express";
import fs from "fs/promises";
import path from "path";
import { config } from "../config.js";
import {
  DOMAIN_KEYWORDS_FILE,
  FILTERED_DIR,
  filterDomainsFromFile,
  filterLatestDownload,
  listFilteredResults,
  loadDomainKeywords,
  readFilteredJson,
  saveDomainKeywords,
} from "../domainFilter.js";

export const domainFilterRouter = Router();

domainFilterRouter.get("/keywords", async (_req, res) => {
  res.json({ keywords: await loadDomainKeywords() });
});

domainFilterRouter.post("/keywords", async (req, res) => {
  const keyword = String(req.body?.keyword ?? "").trim().toLowerCase();
  if (!keyword) {
    return res.status(400).json({ error: "keyword is required" });
  }
  const keywords = await loadDomainKeywords();
  if (keywords.includes(keyword)) {
    return res.status(409).json({ error: "Keyword already exists" });
  }
  keywords.push(keyword);
  res.json({ keywords: await saveDomainKeywords(keywords) });
});

domainFilterRouter.delete("/keywords/:keyword", async (req, res) => {
  const keyword = decodeURIComponent(req.params.keyword).trim().toLowerCase();
  const keywords = (await loadDomainKeywords()).filter((k) => k !== keyword);
  res.json({ keywords: await saveDomainKeywords(keywords) });
});

domainFilterRouter.put("/keywords", async (req, res) => {
  if (!Array.isArray(req.body?.keywords)) {
    return res.status(400).json({ error: "keywords must be an array" });
  }
  res.json({ keywords: await saveDomainKeywords(req.body.keywords) });
});

/** GET /api/domain-filter/results — latest or ?file=name.json */
domainFilterRouter.get("/results", async (req, res) => {
  try {
    const file = req.query.file;
    if (file) {
      const data = await readFilteredJson(String(file));
      return res.json(data);
    }
    const files = await listFilteredResults();
    if (!files.length) {
      return res.json({
        matchedCount: 0,
        domains: [],
        files: [],
      });
    }
    const latest = files[0];
    const data = await readFilteredJson(latest.name);
    res.json({ ...data, files });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

/** POST /api/domain-filter/run — filter latest .txt or { filename } */
domainFilterRouter.post("/run", async (req, res) => {
  try {
    const filename = req.body?.filename;
    const result = filename
      ? await filterDomainsFromFile(
          path.join(config.downloadDir, path.basename(String(filename)))
        )
      : await filterLatestDownload();
    res.json(result);
  } catch (e) {
    res.status(400).json({ error: String(e) });
  }
});

domainFilterRouter.get("/files", async (_req, res) => {
  res.json({ files: await listFilteredResults() });
});

/** GET /api/domain-filter/download?format=txt|json&file=optional — download filtered results */
domainFilterRouter.get("/download", async (req, res) => {
  try {
    const format = String(req.query.format ?? "txt").toLowerCase();
    const fileParam = req.query.file;

    let filename;
    if (fileParam) {
      filename = path.basename(String(fileParam));
    } else {
      const files = await listFilteredResults();
      if (!files.length) {
        return res.status(404).json({ error: "No filtered results found" });
      }
      filename = files[0].name;
    }

    const filePath = path.join(FILTERED_DIR, filename);
    await fs.access(filePath);

    if (format === "json") {
      return res.download(filePath, filename);
    }

    if (format === "txt") {
      const data = await readFilteredJson(filename);
      const domains = (data.domains ?? []).map((row) => row.domain).filter(Boolean);
      const txtName = filename.replace(/\.json$/i, "_domains.txt");
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="${txtName}"`
      );
      return res.send(domains.length ? `${domains.join("\n")}\n` : "");
    }

    return res.status(400).json({ error: "format must be txt or json" });
  } catch (e) {
    if (e?.code === "ENOENT") {
      return res.status(404).json({ error: "Filtered file not found" });
    }
    res.status(500).json({ error: String(e) });
  }
});

domainFilterRouter.delete("/results", async (req, res) => {
  const file = req.query.file;
  try {
    if (file) {
      await fs.rm(
        path.join(path.dirname(DOMAIN_KEYWORDS_FILE), "filtered", path.basename(String(file))),
        { force: true }
      );
    } else {
      const dir = path.join(path.dirname(DOMAIN_KEYWORDS_FILE), "filtered");
      const files = await fs.readdir(dir).catch(() => []);
      await Promise.all(
        files.map((f) => fs.rm(path.join(dir, f), { force: true }))
      );
    }
    res.json({ cleared: true });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});
