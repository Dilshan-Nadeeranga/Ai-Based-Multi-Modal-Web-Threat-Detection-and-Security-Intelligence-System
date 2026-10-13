/**
 * Keep-alive self-ping for Render free tier.
 * Render provides RENDER_EXTERNAL_URL automatically.
 * Pings /api/health every KEEP_ALIVE_INTERVAL_MS to prevent the service sleeping.
 */

const PING_URL = process.env.RENDER_EXTERNAL_URL
  ? `${process.env.RENDER_EXTERNAL_URL}/api/health`
  : null;

const INTERVAL_MS = Number(process.env.KEEP_ALIVE_INTERVAL_MS ?? 5 * 60 * 1000); // 5 min

export function startKeepAlive() {
  if (!PING_URL) {
    // Not on Render — skip silently
    return;
  }

  console.log(`[keep-alive] Pinging ${PING_URL} every ${INTERVAL_MS / 60000} min`);

  setInterval(async () => {
    try {
      const res = await fetch(PING_URL, {
        signal: AbortSignal.timeout(10_000),
        headers: { "User-Agent": "ThreatRadar-KeepAlive/1.0" },
      });
      if (!res.ok) {
        console.warn(`[keep-alive] Ping returned ${res.status}`);
      }
    } catch (err) {
      console.warn("[keep-alive] Ping failed:", err.message);
    }
  }, INTERVAL_MS);
}
