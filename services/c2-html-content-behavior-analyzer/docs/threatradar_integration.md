# ThreatRadar → C2 integration (Part 9 B-2)

This is for the ThreatRadar maintainer. ThreatRadar finds URLs (Telegram channels, subreddits,
newly registered domains); C2 analyses each page (DOM + multilingual text + static JS behaviour)
and gives it a verdict, a threat class and a risk score. **C2 does not change any ThreatRadar
code.** Everything below is what ThreatRadar has to add on its side.

## How it works

```
ThreatRadar ──POST /api/v1/ingest──▶ C2 (202 at once) ──queue──▶ worker (2 at a time, 1 job/s)
                                                                    │ 9B-1 engine: safe fetch + models
                                                                    ▼
                         dashboard ◀── /api/v1/scans, /stats, /feed/stream (live)
```

- **Push (main path).** ThreatRadar sends new URLs to C2. C2 only checks and queues them and
  answers **202** straight away; it never makes ThreatRadar wait for an analysis.
- **Pull (backup).** Once a day C2 reads ThreatRadar's output files (`scraped/urls_only.csv`,
  `scraped/reddit_urls_only.csv`, `filtered/filtered_domains_*.json`) and queues URLs it has never
  seen. A push that got lost is picked up there. ThreatRadar doesn't need to do anything for this.
- C2 skips a URL it analysed in the last 24 h (it reuses that result) and skips allow-listed
  sites (youtube.com, google.com, … see `configs/threatradar_rules.yaml`), so sending a URL twice
  is harmless.

## Environment variables (ThreatRadar side)

| Variable | Example | Meaning |
|---|---|---|
| `C2_INGEST_URL` | `http://127.0.0.1:8002/api/v1/ingest` | C2's ingest endpoint |
| `C2_INGEST_KEY` | *(long random string)* | Shared secret. Must equal C2's `INGEST_API_KEY` |

C2 side: put the same value in C2's `.env` as `INGEST_API_KEY=...`. Generate it once with
`python -c "import secrets; print(secrets.token_urlsafe(32))"` and share it privately, never in
git. While `INGEST_API_KEY` is empty, C2 answers **503** (ingest is off).

> If ThreatRadar runs on Render and C2 runs on a laptop, Render can't reach `127.0.0.1`, so the
> push fails. In that case the daily pull is what feeds C2, or expose C2 through the team
> gateway / a tunnel and set `C2_INGEST_URL` to that address.

## The request

```
POST {C2_INGEST_URL}
Content-Type: application/json
X-C2-Ingest-Key: {C2_INGEST_KEY}

{
  "source": "threatradar_push",
  "urls": [
    { "url": "https://paypa1-secure-login.com/verify",
      "source_ref": { "channel": "lk_deals", "message_id": 4521 } },
    { "url": "https://usdt-double.xyz/",
      "source_ref": { "subreddit": "CryptoScams", "post_id": "1abcde" } },
    { "url": "https://bank-lk-verify.top/",
      "source_ref": { "reasons": ["brand_mimicry:bank", "keyword:verify"] } }
  ]
}
```

- `url`: required. `http`/`https` only, at most 2,048 characters. For a bare domain from the
  domain filter, send `https://<domain>/`.
- `source_ref`: optional; send what you have. Telegram: `channel`, `message_id`. Reddit:
  `subreddit`, `post_id`. Domain filter: `reasons`. Reviewers see it, and C2 uses it to pick
  the dataset source (Telegram / Reddit → `social_media_report`, everything else → `other`).
  Unknown extra fields are ignored.
- At most **500 URLs per request**.

### Answers

| Status | Meaning | What ThreatRadar does |
|---|---|---|
| **202** | Queued. Body below. | Done. Don't resend. |
| 401 | Key missing or wrong | Fix `C2_INGEST_KEY`. Don't retry. |
| 415 / 422 | Not JSON / invalid body (e.g. more than 500 URLs, empty list) | Fix the request. Don't retry. |
| 503 | Ingest is off (C2 has no `INGEST_API_KEY`) | Retry later. |
| no answer / 5xx | C2 is down or restarting | Retry later. |

```json
{ "accepted": 2, "duplicates": 0, "queue_depth": 2, "job_ids": [41, 42],
  "rejected": [ { "index": 2, "url": "hxxps://www[.]youtube[.]com/", "reason": "allow-listed" } ] }
```

One bad URL never fails the whole batch. It's listed in `rejected` (with its position in your
list) and the other URLs are still accepted. `job_ids` = accepted + duplicate jobs, in input
order.

## Batching and retries

- **Batching:** collect new URLs and send them **once a minute** (or as soon as 100 are waiting),
  one request with up to 500 URLs. Sending each URL right away also works but costs more requests.
- **Retry rule:** retry **only** on a network error, **5xx** or **503**. Wait 30 s, then 1 min,
  2 min, 4 min, … up to 30 min. Give up after about 6 tries: the daily pull still picks the URLs
  up. **Never retry 401 / 415 / 422**, because the same request will fail again.
- Where to call it: after a Telegram/Reddit scrape batch has appended rows to its CSV, and after
  `domainFilter.js` writes `filtered_domains_<date>.json`.

## Node.js snippet (ES modules, Node 18+ built-in `fetch`)

```js
// c2Client.js - collect URLs, push them to C2 once a minute, retry only on 5xx / network errors
const queue = []; let delay = 30_000;
export function sendToC2(url, sourceRef = {}) { queue.push({ url, source_ref: sourceRef }); }
async function flush() {
  if (!queue.length || !process.env.C2_INGEST_URL) return setTimeout(flush, 60_000);
  const batch = queue.splice(0, 500);
  try {
    const res = await fetch(process.env.C2_INGEST_URL, { method: "POST",
      headers: { "Content-Type": "application/json", "X-C2-Ingest-Key": process.env.C2_INGEST_KEY },
      body: JSON.stringify({ source: "threatradar_push", urls: batch }) });
    if (res.status >= 500) throw new Error(`C2 answered ${res.status}`);
    if (res.status !== 202) console.error("[c2] rejected batch:", res.status, await res.text());
    delay = 30_000; setTimeout(flush, 60_000);
  } catch (err) { queue.unshift(...batch); console.warn("[c2] retry:", err.message);
    setTimeout(flush, delay); delay = Math.min(delay * 2, 30 * 60_000); }
}
setTimeout(flush, 60_000);
```

Usage: `import { sendToC2 } from "./c2Client.js"; sendToC2("https://x.example/", { channel: "lk_deals", message_id: 12 });`

## Daily backup pull (C2 side, Windows Task Scheduler)

The C2 maintainer runs this once, in a terminal, on the machine where C2 runs (adjust the paths;
the C2 API must be running so its worker analyses what the pull queues):

```
schtasks /Create /SC DAILY /ST 03:00 /TN "C2 ThreatRadar pull" /TR "\"D:\4Y Project\J26-SE-316\services\c2-html-content-behavior-analyzer\.venv\Scripts\python.exe\" \"D:\4Y Project\J26-SE-316\services\c2-html-content-behavior-analyzer\scripts\pull_threatradar.py\" --dir \"D:\4Y Project\J26-SE-316\ingestion\threat-radar\backend\data\""
```

Manual run: `python scripts/pull_threatradar.py --dir ..\..\ingestion\threat-radar\backend\data`
(first time, consider `--since <recent date>` or `--limit 200`: the worker does 1 URL per second).

## What happens with the results

- The dashboard reads `GET /api/v1/scans`, `GET /api/v1/scans/{id}`, `GET /api/v1/stats/overview`
  and the live feed `GET /api/v1/feed/stream` (Server-Sent Events). Every URL there is
  **defanged** (`hxxps://example[.]com`, so it can't be clicked), and no page HTML ever leaves C2.
- Malicious results, and Suspicious results with risk ≥ 70, go to a **human review queue**
  (`scripts/review_live.py`). Only confirmed ones are exported to the dataset's manual feed.
  Live results are never added to training data automatically.
