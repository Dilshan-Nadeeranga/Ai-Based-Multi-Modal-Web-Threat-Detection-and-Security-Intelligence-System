import api from '../../api/api.js'

const PROBE_TIMEOUT_MS = 4000

export const SERVICES = [
  { id: 'c1', label: 'C1 URL & Domain Analyzer', url: `${import.meta.env.VITE_C1_URL || 'http://localhost:8001'}/health` },
  { id: 'c2', label: 'C2 HTML Content & Behavior Analyzer', url: `${import.meta.env.VITE_C2_URL || 'http://localhost:8002'}/health` },
  { id: 'c3', label: 'C3 Social & Visual Analyzer', url: `${import.meta.env.VITE_C3_URL || 'http://localhost:8003'}/health` },
  {
    id: 'c4',
    label: 'C4 Code Vulnerability Auditor',
    url: `${import.meta.env.VITE_C4_API_BASE_URL || 'http://localhost:8000/api/v1'}/health`,
  },
]

/**
 * Services may not allow this origin via CORS, so the probe uses no-cors: an opaque
 * response still proves the service answered, while a network error means it is down.
 */
async function probe(url) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), PROBE_TIMEOUT_MS)
  try {
    await fetch(url, { mode: 'no-cors', cache: 'no-store', signal: controller.signal })
    return 'online'
  } catch {
    return 'offline'
  } finally {
    clearTimeout(timer)
  }
}

export async function checkGateway() {
  try {
    const { data } = await api.get('/health', { timeout: PROBE_TIMEOUT_MS })
    return { gateway: data?.status === 'ok' ? 'online' : 'offline', database: data?.database_connected ? 'online' : 'offline' }
  } catch {
    return { gateway: 'offline', database: 'unknown' }
  }
}

export async function checkServices() {
  const results = await Promise.all(SERVICES.map((service) => probe(service.url)))
  return Object.fromEntries(SERVICES.map((service, index) => [service.id, results[index]]))
}
