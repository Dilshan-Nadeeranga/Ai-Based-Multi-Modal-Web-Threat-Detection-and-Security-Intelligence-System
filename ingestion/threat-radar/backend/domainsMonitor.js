import { config } from "./config.js";

export class DomainsMonitorError extends Error {
  constructor(message) {
    super(message);
    this.name = "DomainsMonitorError";
  }
}

function buildUrl(...parts) {
  const p = parts.map((x) => String(x).replace(/^\/|\/$/g, "")).join("/");
  return `${config.apiBase}/${config.token}/${p}/`;
}

async function apiGet(...parts) {
  if (!config.token || config.token === "your_token_here") {
    throw new DomainsMonitorError(
      "No API token. Set DOMAINS_MONITOR_TOKEN in backend/.env"
    );
  }
  const target = buildUrl(...parts);
  const res = await fetch(target, {
    signal: AbortSignal.timeout(config.timeoutMs),
    headers: { "User-Agent": "ThreatRadar/1.0" },
  });
  if (!res.ok) {
    const body = (await res.text()).slice(0, 200);
    throw new DomainsMonitorError(
      `API failed [${res.status}] ${target.replace(config.token, "***")}: ${body}`
    );
  }
  return res;
}

export async function getAccount() {
  return (await apiGet("account", "json")).json();
}

export async function fetchFeedJson(feedType) {
  return (await apiGet(feedType, "json")).json();
}

export async function downloadList(zone, fmt, variant = "get") {
  const res = await apiGet(variant, zone, "list", fmt);
  const ext = fmt === "text" ? "txt" : "zip";
  return {
    buffer: Buffer.from(await res.arrayBuffer()),
    filename: `${zone}_${variant}_${fmt}.${ext}`,
  };
}

export function feedDomainCount(payload) {
  if (payload && typeof payload === "object" && "domain" in payload) {
    const d = payload.domain;
    return Array.isArray(d) ? d.length : null;
  }
  return null;
}
