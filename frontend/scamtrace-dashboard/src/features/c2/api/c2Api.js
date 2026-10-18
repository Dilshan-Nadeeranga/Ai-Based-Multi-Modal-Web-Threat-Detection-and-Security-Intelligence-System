// API client for the C2 HTML Content & Behavior Analyzer (contract: services/c2-.../docs/api_contract.md).
// Same env pattern as the rest of the dashboard (see features/dashboard/serviceHealth.js).

export const C2_BASE_URL = (import.meta.env.VITE_C2_URL || 'http://localhost:8002').replace(/\/$/, '')

const DEFAULT_TIMEOUT_MS = 15000
const ANALYZE_TIMEOUT_MS = 60000

export class C2ApiError extends Error {
  /** kind: 'network' | 'timeout' | 'http' */
  constructor(message, { status = 0, kind = 'http', body = null } = {}) {
    super(message)
    this.status = status
    this.kind = kind
    this.body = body
  }
}

async function request(path, { method = 'GET', body, timeout = DEFAULT_TIMEOUT_MS, signal } = {}) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort('timeout'), timeout)
  const onAbort = () => controller.abort('cancelled')
  signal?.addEventListener('abort', onAbort)
  let response
  try {
    response = await fetch(`${C2_BASE_URL}${path}`, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
      cache: 'no-store',
    })
  } catch {
    if (controller.signal.reason === 'timeout') {
      throw new C2ApiError(`C2 did not answer within ${Math.round(timeout / 1000)} s.`, { kind: 'timeout' })
    }
    if (controller.signal.reason === 'cancelled') throw new C2ApiError('Cancelled.', { kind: 'cancelled' })
    throw new C2ApiError(`Cannot reach the C2 service at ${C2_BASE_URL}. Start it with "python scripts/run_api.py".`, {
      kind: 'network',
    })
  } finally {
    clearTimeout(timer)
    signal?.removeEventListener('abort', onAbort)
  }
  const data = await response.json().catch(() => null)
  if (!response.ok) {
    let message = typeof data?.detail === 'string' ? data.detail : `C2 answered HTTP ${response.status}`
    if (response.status === 429) {
      message = `Too many analyses — wait ${response.headers.get('Retry-After') || 'a few'} s and try again.`
    }
    throw new C2ApiError(message, { status: response.status, body: data })
  }
  return data
}

/** POST /api/v1/analyze. A 504 carries the PARTIAL AnalysisResponse: it is returned, marked partial. */
export async function analyze({ url, html }, { signal } = {}) {
  const body = html ? { html, url: url || undefined, source: 'user' } : { url, source: 'user' }
  try {
    return await request('/api/v1/analyze', { method: 'POST', body, timeout: ANALYZE_TIMEOUT_MS, signal })
  } catch (error) {
    if (error.status === 504 && error.body?.analysis_id) return { ...error.body, partial: true }
    throw error
  }
}

/** GET /ready -> {ready, loading, reason, ...}; 503 still carries the body. */
export async function getReady({ timeout = 4000 } = {}) {
  try {
    return await request('/ready', { timeout })
  } catch (error) {
    if (error.status === 503 && error.body) return error.body
    throw error
  }
}

function query(params) {
  const search = new URLSearchParams()
  Object.entries(params || {}).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') search.set(key, String(value))
  })
  const text = search.toString()
  return text ? `?${text}` : ''
}

export const getScans = (params, options) => request(`/api/v1/scans${query(params)}`, options)
export const getScan = (id, options) => request(`/api/v1/scans/${encodeURIComponent(id)}`, options)
export const getStats = (window, options) => request(`/api/v1/stats/overview${query({ window })}`, options)
export const getResearch = (options) => request('/api/v1/research/summary', options)

/** URL of the Server-Sent Events live feed (used with new EventSource(...)). */
export const feedStreamUrl = () => `${C2_BASE_URL}/api/v1/feed/stream`
