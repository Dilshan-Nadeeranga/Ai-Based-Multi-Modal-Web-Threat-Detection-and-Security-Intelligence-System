import { Router } from "express";
import fs from "fs/promises";
import path from "path";
import { config } from "../config.js";
import { filterLatestDownload } from "../domainFilter.js";
import { DomainsMonitorError, runDownload } from "../downloadJob.js";
import { fetchFeedJson, getAccount } from "../domainsMonitor.js";
import { dailyJob } from "../scheduler.js";

export const apiRouter = Router();

apiRouter.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    service: "threatradar-backend",
    autoDownload: config.autoDownload,
    downloadCron: config.downloadCron,
    dailyZone: config.dailyZone,
  });
});

apiRouter.get("/account", async (_req, res) => {
  try {
    res.json(await getAccount());
  } catch (e) {
    res.status(502).json({ error: String(e) });
  }
});

apiRouter.get("/downloads", async (_req, res) => {
  try {
    await fs.mkdir(config.downloadDir, { recursive: true });
    const files = await fs.readdir(config.downloadDir);
    const stats = await Promise.all(
      files.map(async (name) => {
        const p = path.join(config.downloadDir, name);
        const s = await fs.stat(p);
        return { name, bytes: s.size, modified: s.mtime.toISOString() };
      })
    );
    res.json({
      dir: config.downloadDir,
      files: stats.sort((a, b) => b.modified.localeCompare(a.modified)),
    });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

apiRouter.post("/download", async (req, res) => {
  const zone = String(req.body?.zone ?? "dailyupdate");
  const format = String(req.body?.format ?? "text");
  const useFeed = Boolean(req.body?.useFeed);
  const dated = Boolean(req.body?.dated);

  try {
    const result = await runDownload({ zone, format, useFeed, dated });
    if (format === "text" && !useFeed) {
      try {
        const filtered = await filterLatestDownload();
        result.filtered = {
          saved: filtered.saved,
          matchedCount: filtered.matchedCount,
          totalScanned: filtered.totalScanned,
        };
      } catch {
        /* filter optional if no keywords configured */
      }
    }
    res.json(result);
  } catch (e) {
    const status = e instanceof DomainsMonitorError ? 502 : 500;
    res.status(status).json({ error: String(e) });
  }
});

/** Run the same job as the daily scheduler (dated filename). */
apiRouter.post("/download/daily", async (_req, res) => {
  try {
    const result = await dailyJob();
    res.json(result);
  } catch (e) {
    const status = e instanceof DomainsMonitorError ? 502 : 500;
    res.status(status).json({ error: String(e) });
  }
});

apiRouter.get("/downloads/:filename", async (req, res) => {
  const safe = path.basename(req.params.filename);
  const filePath = path.join(config.downloadDir, safe);
  try {
    await fs.access(filePath);
    res.download(filePath);
  } catch {
    res.status(404).json({ error: "File not found" });
  }
});

apiRouter.get("/feed/:feedType/preview", async (req, res) => {
  const limit = Math.min(Number(req.query.limit ?? 20), 500);
  try {
    const payload = await fetchFeedJson(req.params.feedType);
    if (payload && typeof payload === "object" && "domain" in payload) {
      const domains = payload.domain;
      return res.json({
        total: domains.length,
        preview: domains.slice(0, limit),
      });
    }
    res.json(payload);
  } catch (e) {
    res.status(502).json({ error: String(e) });
  }
});
