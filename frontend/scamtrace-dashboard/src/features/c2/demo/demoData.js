// Demo mode (presentation safety net): bundled fixtures exported from REAL C2 output by
// services/c2-.../scripts/export_ui_fixtures.py (URLs already defanged). Loaded lazily, so the
// dashboard's main bundle does not carry them.

let cache = null

export function loadDemo() {
  cache ??= Promise.all([
    import('../fixtures/analyses.json'),
    import('../fixtures/scans.json'),
    import('../fixtures/scan_details.json'),
    import('../fixtures/stats.json'),
    import('../fixtures/research.json'),
  ]).then(([analyses, scans, details, stats, research]) => ({
    analyses: analyses.default,
    scans: scans.default,
    details: details.default,
    stats: stats.default,
    research: research.default,
  }))
  return cache
}

export const DEMO_EXAMPLES = [
  { key: 'benign_sinhala', label: 'Sinhala news page', hint: 'Legitimate, language caveat', input: 'hxxps://www[.]lankadeepa[.]lk/latest_news' },
  { key: 'phishing_zimbra', label: 'Zimbra webmail phishing', hint: 'Malicious, evidence floor', input: 'hxxps://it-corp[.]netlify[.]app/' },
  { key: 'crypto_scam', label: 'Crypto investment scam', hint: 'Malicious, crypto_scam', input: 'hxxps://digitalapexminingtech[.]com/' },
  { key: 'unreachable', label: 'Taken-down URL', hint: 'Unreachable, no verdict', input: 'hxxps://c2-demo-unreachable[.]invalid/login' },
]

/** Pick the fixture that best matches what was typed (keywords), default = the phishing page. */
export function pickDemoAnalysis(analyses, input) {
  const text = String(input || '').toLowerCase()
  const exact = DEMO_EXAMPLES.find((example) => text && example.input.toLowerCase() === text)
  if (exact) return analyses[exact.key]
  if (/unreach|invalid|offline|gone|dead/.test(text)) return analyses.unreachable
  if (/crypto|coin|usdt|btc|mining|invest/.test(text)) return analyses.crypto_scam
  if (/lankadeepa|sinhala|news|lk\b|\.lk/.test(text)) return analyses.benign_sinhala
  return analyses.phishing_zimbra
}

const sleep = (ms, signal) =>
  new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms)
    signal?.addEventListener('abort', () => {
      clearTimeout(timer)
      reject(new DOMException('Aborted', 'AbortError'))
    })
  })

/** Simulated round trip: the recorded answer after roughly its real processing time. */
export async function demoAnalyze(input, { signal } = {}) {
  const { analyses } = await loadDemo()
  const result = pickDemoAnalysis(analyses, input)
  const total = result.timings_ms?.total || 900
  await sleep(Math.min(Math.max(total * 3, 1800), 3200), signal)
  return { ...result, analyzed_at: new Date().toISOString(), demo: true }
}

/** Client-side version of GET /api/v1/scans over the fixture list. */
export function filterScans(items, { source, verdict, threat_class: threatClass, q } = {}) {
  const needle = (q || '').trim().toLowerCase()
  return items.filter((item) => {
    if (source && item.source !== source) return false
    if (verdict === 'none' ? item.verdict !== null : verdict && item.verdict !== verdict) return false
    if (threatClass && item.threat_class !== threatClass) return false
    if (needle) {
      const haystack = `${item.url} ${item.final_domain || ''}`.toLowerCase().replaceAll('[.]', '.')
      if (!haystack.includes(needle.replaceAll('[.]', '.'))) return false
    }
    return true
  })
}
