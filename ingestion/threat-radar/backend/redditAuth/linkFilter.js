const REDDIT_HOST_SUFFIXES = [
  "reddit.com", "redd.it", "redditmedia.com", "redditstatic.com",
];

const KNOWN_SUFFIXES = [
  ...REDDIT_HOST_SUFFIXES,
  "t.me", "telegram.org", "telegra.ph",
  "x.com", "twitter.com", "facebook.com", "fb.com",
  "instagram.com", "google.com", "youtube.com", "youtu.be",
  "discord.com", "discord.gg", "github.com", "linkedin.com",
  "tiktok.com", "binance.com", "coinbase.com",
  "wikipedia.org", "imgur.com", "apple.com", "microsoft.com",
];

function host(url) {
  try {
    const u = url.startsWith("http") ? url : `https://${url.replace(/^\/\//, "")}`;
    return new URL(u).hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return "";
  }
}

export function extractDomain(url) {
  return host(url);
}

export function isRedditHost(urlOrHost) {
  const h = urlOrHost.includes("://")
    ? host(urlOrHost)
    : String(urlOrHost).replace(/^www\./, "").toLowerCase();
  if (!h) return true;
  if (h.includes("reddit")) return true;
  return REDDIT_HOST_SUFFIXES.some((s) => h === s || h.endsWith(`.${s}`));
}

function isPlausibleHost(hostname) {
  if (!hostname || !hostname.includes(".")) return false;
  const h = hostname.replace(/^www\./, "").toLowerCase();
  const parts = h.split(".");
  if (parts.length < 2) return false;

  const tld = parts[parts.length - 1];
  // Real TLDs are letters (com, net, io) — blocks 99.99, 10.000, 151.80.36.122
  if (!/^[a-z]{2,63}$/.test(tld)) return false;

  const label = parts.slice(0, -1).join(".");
  if (!/[a-z]/i.test(label)) return false;

  if (/^\d+\.\d+$/.test(h)) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return false;

  return true;
}

export function isExternalCandidate(url) {
  const h = host(url);
  if (!h || !isPlausibleHost(h)) return false;
  if (isRedditHost(h)) return false;

  const extra = (process.env.REDDIT_KNOWN_HOST_WHITELIST ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const blocked = [...KNOWN_SUFFIXES, ...extra];

  return !blocked.some((s) => h === s || h.endsWith(`.${s}`));
}

export function filterUrls(urls) {
  return [...new Set(urls.filter(isExternalCandidate))];
}

function normalizeRawUrl(raw) {
  let u = raw.trim().replace(/[.,);>\]"']+$/, "");
  if (!u) return null;
  if (u.startsWith("//")) u = `https:${u}`;
  if (!/^https?:\/\//i.test(u)) {
    if (/^www\./i.test(u) || /^[\w-]+(\.[\w-]+)+\/\S+/i.test(u) || /^[\w-]+(\.[\w-]+)+$/i.test(u)) {
      u = `https://${u}`;
    } else {
      return null;
    }
  }
  try {
    const parsed = new URL(u);
    if (!isPlausibleHost(parsed.hostname)) return null;
    return parsed.href;
  } catch {
    return null;
  }
}

export function extractUrls(text) {
  if (!text) return [];
  const found = new Set();

  const patterns = [
    /https?:\/\/[^\s<>"']+/gi,
    /(?:www\.)?(?:[a-z0-9][-a-z0-9]*\.)+[a-z]{2,}(?:\/[^\s<>"']*)?/gi,
  ];

  for (const re of patterns) {
    for (const match of text.matchAll(re)) {
      const normalized = normalizeRawUrl(match[0]);
      if (normalized) found.add(normalized);
    }
  }

  return filterUrls([...found]);
}
