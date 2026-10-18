import { useEffect, useRef, useState } from 'react'
import { feedStreamUrl, getScans } from '../api/c2Api.js'
import { loadDemo } from '../demo/demoData.js'

const POLL_MS = 10000
const DEMO_STEP_MS = 3500
const MAX_ITEMS = 100
const SSE_FAILURES_BEFORE_POLLING = 2

/** A Server-Sent `scan` event -> the row shape of GET /api/v1/scans. */
function eventToRow(event) {
  return {
    id: event.id,
    url: event.url,
    verdict: event.verdict,
    threat_class: event.threat_class,
    risk_score: event.risk_score,
    status: event.verdict ? 'ok' : 'no verdict',
    language: null,
    source: event.source,
    created_at: event.created_at,
  }
}

function merge(fresh, current) {
  const seen = new Set()
  return [...fresh, ...current].filter((item) => !seen.has(item.id) && seen.add(item.id)).slice(0, MAX_ITEMS)
}

/**
 * Live list of finished scans.
 * - live: last 25 from /api/v1/scans, then one row per SSE `scan` event (GET /api/v1/feed/stream);
 *   if the stream keeps failing, falls back to polling /api/v1/scans every 10 s.
 * - demo: the bundled scans, replayed one by one as a scripted feed.
 * Returns { items, mode: 'connecting'|'live'|'polling'|'demo'|'error', error, freshIds, lastEventAt }.
 */
export function useLiveFeed(demo) {
  const [state, setState] = useState({ items: [], mode: 'connecting', error: null, freshIds: new Set(), lastEventAt: null, key: null })
  const key = demo ? 'demo' : 'live'
  const timers = useRef([])

  useEffect(() => {
    let active = true
    const controller = new AbortController()
    const clearTimers = () => {
      timers.current.forEach((id) => clearInterval(id))
      timers.current = []
    }
    const update = (patch) => active && setState((previous) => ({ ...previous, key, ...(typeof patch === 'function' ? patch(previous) : patch) }))
    const push = (rows) =>
      update((previous) => ({
        items: merge(rows, previous.items),
        freshIds: new Set(rows.map((row) => row.id)),
        lastEventAt: Date.now(),
      }))

    if (demo) {
      loadDemo().then(({ scans, details }) => {
        const withDetail = scans.items.filter((item) => details[String(item.id)])
        const pool = withDetail.length ? withDetail : scans.items
        const now = Date.now()
        const initial = pool.slice(0, 10).map((item, index) => ({ ...item, created_at: new Date(now - (index + 1) * 95000).toISOString() }))
        update({ items: initial, mode: 'demo', error: null, freshIds: new Set() })
        let next = 10
        const id = setInterval(() => {
          const item = pool[next % pool.length]
          next += 1
          push([{ ...item, created_at: new Date().toISOString() }])
        }, DEMO_STEP_MS)
        timers.current.push(id)
      })
      return () => {
        active = false
        clearTimers()
      }
    }

    let source = null
    let failures = 0
    let polling = false
    const poll = () =>
      getScans({ limit: 25 }, { signal: controller.signal })
        .then((data) => update((previous) => ({ items: merge(data.items, previous.items), error: null })))
        .catch((error) => error.kind !== 'cancelled' && update({ error }))

    const startPolling = () => {
      if (polling) return
      polling = true
      source?.close()
      update({ mode: 'polling' })
      timers.current.push(setInterval(poll, POLL_MS))
    }

    getScans({ limit: 25 }, { signal: controller.signal })
      .then((data) => {
        update({ items: data.items, error: null })
        if (typeof EventSource === 'undefined') return startPolling()
        source = new EventSource(feedStreamUrl())
        source.addEventListener('open', () => {
          failures = 0
          update({ mode: 'live' })
        })
        source.addEventListener('scan', (message) => {
          try {
            push([eventToRow(JSON.parse(message.data))])
          } catch {
            /* malformed event: ignored */
          }
        })
        source.addEventListener('error', () => {
          failures += 1
          if (failures >= SSE_FAILURES_BEFORE_POLLING) startPolling()
        })
      })
      .catch((error) => {
        if (error.kind === 'cancelled') return
        update({ mode: 'error', error })
      })

    return () => {
      active = false
      controller.abort()
      source?.close()
      clearTimers()
    }
  }, [demo, key])

  const current = state.key === key
  return {
    items: current ? state.items : [],
    mode: current ? state.mode : 'connecting',
    error: current ? state.error : null,
    freshIds: current ? state.freshIds : new Set(),
    lastEventAt: current ? state.lastEventAt : null,
  }
}
