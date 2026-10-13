import fs from "fs/promises";
import path from "path";
import { config } from "./config.js";
import {
  DomainsMonitorError,
  downloadList,
  feedDomainCount,
  fetchFeedJson,
} from "./domainsMonitor.js";

/** @returns {string} YYYY-MM-DD in UTC */
export function todayStamp() {
  return new Date().toISOString().slice(0, 10);
}

/**
 * Download a domain list and save to disk.
 * @param {{ zone?: string, format?: string, useFeed?: boolean, outDir?: string, dated?: boolean, outputName?: string }} opts
 */
export async function runDownload(opts = {}) {
  const zone = opts.zone ?? "dailyupdate";
  const format = opts.format ?? "text";
  const useFeed = Boolean(opts.useFeed);
  const outDir = opts.outDir ?? config.downloadDir;
  const dated = Boolean(opts.dated);

  await fs.mkdir(outDir, { recursive: true });

  if (useFeed || format === "json") {
    const payload = await fetchFeedJson(zone);
    const name =
      opts.outputName ??
      (dated ? `${zone}_${todayStamp()}.json` : `${zone}.json`);
    const outPath = path.join(outDir, name);
    await fs.writeFile(outPath, JSON.stringify(payload, null, 2), "utf-8");
    const bytes = (await fs.stat(outPath)).size;
    return {
      saved: name,
      path: outPath,
      bytes,
      domainCount: feedDomainCount(payload),
    };
  }

  const { buffer } = await downloadList(zone, format);
  const name =
    opts.outputName ??
    (dated
      ? `${zone}_${todayStamp()}.${format === "text" ? "txt" : format}`
      : `${zone}_get_${format}.${format === "text" ? "txt" : format}`);
  const outPath = path.join(outDir, name);
  await fs.writeFile(outPath, buffer);

  const lineCount =
    format === "text"
      ? buffer.toString("utf-8").split("\n").filter(Boolean).length
      : null;

  return {
    saved: name,
    path: outPath,
    bytes: buffer.length,
    lineCount,
  };
}

export { DomainsMonitorError };
