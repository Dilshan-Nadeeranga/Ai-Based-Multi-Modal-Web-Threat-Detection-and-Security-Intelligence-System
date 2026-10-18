import { useEffect, useState } from 'react'
import { ChevronLeft, ChevronRight, History, Search } from 'lucide-react'
import { getScans } from '../api/c2Api.js'
import ScanTable, { ScanFilters } from '../components/ScanTable.jsx'
import { Panel, StateBox } from '../components/ui.jsx'
import { filterScans, loadDemo } from '../demo/demoData.js'
import { useAsyncData } from '../hooks/useAsyncData.js'
import { useDemoMode } from '../hooks/useDemoMode.js'

const PAGE_SIZE = 15

function useDebounced(value, ms = 350) {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const id = setTimeout(() => setDebounced(value), ms)
    return () => clearTimeout(id)
  }, [value, ms])
  return debounced
}

/** Past scans (GET /api/v1/scans): search + filters, cursor pagination (Older / Newer). */
export default function C2History() {
  const { demo } = useDemoMode()
  const [filters, setFilters] = useState({ source: '', verdict: '', threat_class: '' })
  const [search, setSearch] = useState('')
  const q = useDebounced(search.trim())
  // cursors[i] = the cursor that loads page i (page 0 = newest = no cursor)
  const [pages, setPages] = useState({ key: '', cursors: [null], index: 0 })
  const filterKey = `${demo}|${q}|${filters.source}|${filters.verdict}|${filters.threat_class}`
  const view = pages.key === filterKey ? pages : { key: filterKey, cursors: [null], index: 0 }
  const cursor = view.cursors[view.index]

  const { data, error, loading, reload } = useAsyncData(async (signal) => {
    const params = { ...filters, q, limit: PAGE_SIZE }
    if (demo) {
      const { scans } = await loadDemo()
      const matching = filterScans(scans.items, params)
      const start = cursor ? Number(cursor) : 0
      const next = start + PAGE_SIZE < matching.length ? String(start + PAGE_SIZE) : null
      return { items: matching.slice(start, start + PAGE_SIZE), next_cursor: next, total: matching.length }
    }
    return getScans({ ...params, cursor }, { signal })
  }, `${filterKey}|${cursor}`)

  function older() {
    if (!data?.next_cursor) return
    const cursors = [...view.cursors.slice(0, view.index + 1), data.next_cursor]
    setPages({ key: filterKey, cursors, index: view.index + 1 })
  }
  function newer() {
    setPages({ key: filterKey, cursors: view.cursors, index: Math.max(0, view.index - 1) })
  }

  const items = data?.items || []
  return (
    <div className="flex flex-col gap-4">
      <h2 className="flex items-center gap-2 text-xl font-semibold text-[color:var(--c2-fg-strong)]">
        <History className="h-5 w-5 text-[color:var(--c2-accent)]" aria-hidden="true" /> Scan history
      </h2>
      <Panel>
        <div className="flex flex-wrap items-end gap-3">
          <label htmlFor="c2-history-q" className="flex min-w-[16rem] flex-1 flex-col gap-1 text-xs font-medium text-[color:var(--c2-fg-muted)]">
            Search URL or domain
            <span className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-[color:var(--c2-fg-faint)]" aria-hidden="true" />
              <input
                id="c2-history-q"
                type="search"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="e.g. paypal, .xyz, netlify"
                className="w-full rounded-md border border-[color:var(--c2-border-strong)] bg-[color:var(--c2-field)] py-1.5 pl-8 pr-2 text-sm text-[color:var(--c2-fg-hi)] placeholder:text-[color:var(--c2-fg-faint)] focus:border-[color:var(--c2-accent-solid)]"
              />
            </span>
          </label>
          <ScanFilters filters={filters} onChange={setFilters} idPrefix="c2-history" />
        </div>
      </Panel>
      <Panel>
        {!data && loading ? (
          <StateBox state="loading" message="Loading scans…" />
        ) : error ? (
          <StateBox state="error" message={error.message} onRetry={reload} />
        ) : items.length ? (
          <>
            <div className={loading ? 'opacity-60' : ''}>
              <ScanTable items={items} />
            </div>
            <nav className="mt-3 flex items-center justify-between gap-3" aria-label="History pages">
              <button
                type="button"
                onClick={newer}
                disabled={view.index === 0}
                className="inline-flex items-center gap-1 rounded-md border border-[color:var(--c2-border-strong)] px-3 py-1.5 text-sm text-[color:var(--c2-fg)] hover:border-[color:var(--c2-accent-solid)] disabled:cursor-not-allowed disabled:opacity-40"
              >
                <ChevronLeft className="h-4 w-4" aria-hidden="true" /> Newer
              </button>
              <span className="font-mono text-xs text-[color:var(--c2-fg-muted)]">
                page {view.index + 1}
                {data.total !== undefined ? ` · ${data.total} matching` : ''}
              </span>
              <button
                type="button"
                onClick={older}
                disabled={!data.next_cursor}
                className="inline-flex items-center gap-1 rounded-md border border-[color:var(--c2-border-strong)] px-3 py-1.5 text-sm text-[color:var(--c2-fg)] hover:border-[color:var(--c2-accent-solid)] disabled:cursor-not-allowed disabled:opacity-40"
              >
                Older <ChevronRight className="h-4 w-4" aria-hidden="true" />
              </button>
            </nav>
          </>
        ) : (
          <StateBox state="empty" message={q || filters.source || filters.verdict || filters.threat_class ? 'No scan matches this search.' : 'No scans stored yet. Analyze a URL on the Scan tab.'} />
        )}
      </Panel>
    </div>
  )
}
