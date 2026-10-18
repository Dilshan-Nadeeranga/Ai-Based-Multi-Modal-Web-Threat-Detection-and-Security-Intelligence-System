import { useEffect, useMemo, useState } from 'react'
import { Activity, BarChart3, Cpu, Globe2, Languages, Radio, Tags } from 'lucide-react'
import { getStats } from '../api/c2Api.js'
import { CountBars, Sparkline, StatTile } from '../components/Charts.jsx'
import ScanTable, { ScanFilters } from '../components/ScanTable.jsx'
import { Chip, Panel, SegmentedControl, StateBox } from '../components/ui.jsx'
import { CLASS_LABELS, LANGUAGE_LABELS, SOURCE_LABELS } from '../constants.js'
import { filterScans, loadDemo } from '../demo/demoData.js'
import { useAsyncData } from '../hooks/useAsyncData.js'
import { useDemoMode } from '../hooks/useDemoMode.js'
import { useLiveFeed } from '../hooks/useLiveFeed.js'

const STATS_REFRESH_MS = 20000
const FEED_MODE = {
  connecting: { text: 'connecting…', tone: 'slate' },
  live: { text: 'LIVE · server-sent events', tone: 'green' },
  polling: { text: 'polling every 10 s (stream unavailable)', tone: 'amber' },
  demo: { text: 'DEMO · scripted feed', tone: 'amber' },
  error: { text: 'feed unavailable', tone: 'red' },
}
const WORKER_TONE = { idle: 'green', busy: 'cyan', waiting_for_models: 'amber', stopped: 'slate', disabled: 'slate' }
const CLASS_TONES = { phishing: 'bg-[color:var(--c2-mal-solid)]', crypto_scam: 'bg-[color:var(--c2-sus-solid)]', fake_ecommerce: 'bg-[color:var(--c2-violet)]', malware_delivery: 'bg-[color:var(--c2-high-solid)]', benign: 'bg-[color:var(--c2-ok-solid)]' }

function Stats({ demo, period }) {
  const { data, error, loading, reload } = useAsyncData(
    async (signal) => (demo ? (await loadDemo()).stats[period] : getStats(period, { signal })),
    `${demo}-${period}`,
  )
  useEffect(() => {
    if (demo) return undefined
    const id = setInterval(reload, STATS_REFRESH_MS)
    return () => clearInterval(id)
  }, [demo, reload])

  if (!data && loading) return <StateBox state="loading" message="Loading counters…" />
  if (!data && error) return <StateBox state="error" message={error.message} onRetry={reload} />
  if (!data) return null
  const verdicts = data.by_verdict || {}
  const threats = Object.fromEntries(Object.entries(data.by_threat_class || {}).filter(([name]) => name !== 'benign'))
  const worker = data.worker || {}
  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <StatTile label={`Scans · ${period}`} value={data.total} sub={`${data.duplicates_skipped} duplicate(s) skipped`} />
        <StatTile label="Malicious" value={verdicts.Malicious || 0} tone="text-[color:var(--c2-mal)]" />
        <StatTile label="Suspicious" value={verdicts.Suspicious || 0} tone="text-[color:var(--c2-sus)]" />
        <StatTile label="Legitimate" value={verdicts.Legitimate || 0} tone="text-[color:var(--c2-ok)]" />
        <StatTile label="No verdict" value={verdicts.none || 0} tone="text-[color:var(--c2-fg-2)]" sub="unreachable / inconclusive" />
      </div>
      <div className="grid gap-4 lg:grid-cols-4">
        <Panel title={`Scans per ${data.series_bucket}`} icon={BarChart3} className="lg:col-span-2">
          <Sparkline series={data.series} label={`Scans per ${data.series_bucket}`} />
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <Chip tone="cyan">queue {data.queue?.queued ?? 0}</Chip>
            {data.queue?.running > 0 && <Chip tone="cyan">running {data.queue.running}</Chip>}
            {data.queue?.failed > 0 && <Chip tone="amber">failed {data.queue.failed}</Chip>}
            <Chip tone={WORKER_TONE[worker.state] || 'slate'} title={worker.last_error || undefined}>
              <Cpu className="h-3 w-3" aria-hidden="true" /> worker {worker.state || 'unknown'}
              {worker.enabled ? ` · ${worker.concurrency}×, ${worker.jobs_per_second}/s` : ''}
            </Chip>
            <Chip tone="amber">review queue {data.review?.pending ?? 0}</Chip>
          </div>
        </Panel>
        <Panel title="By threat class" icon={Tags}>
          <CountBars counts={threats} labels={CLASS_LABELS} tones={CLASS_TONES} />
        </Panel>
        <Panel title="By source / language" icon={Languages}>
          <CountBars counts={data.by_source} labels={SOURCE_LABELS} />
          <div className="my-3 border-t border-[color:var(--c2-border)]" />
          <CountBars counts={data.by_language} labels={LANGUAGE_LABELS} tone="bg-[color:var(--c2-violet-80)]" />
        </Panel>
      </div>
      {data.top_domains?.length > 0 && (
        <Panel title="Most flagged domains (defanged)" icon={Globe2}>
          <ul className="flex flex-wrap gap-2">
            {data.top_domains.map((domain) => (
              <li key={domain.key}>
                <Chip>
                  {domain.key} <span className="text-[color:var(--c2-fg-muted)]">×{domain.count}</span>
                </Chip>
              </li>
            ))}
            {data.top_brands?.map((brand) => (
              <li key={`brand-${brand.key}`}>
                <Chip tone="red">
                  imitates “{brand.key}” <span className="text-[color:var(--c2-mal-70)]">×{brand.count}</span>
                </Chip>
              </li>
            ))}
          </ul>
        </Panel>
      )}
    </div>
  )
}

export default function C2Feed() {
  const { demo } = useDemoMode()
  const [period, setPeriod] = useState('24h')
  const [filters, setFilters] = useState({ source: '', verdict: '', threat_class: '' })
  const feed = useLiveFeed(demo)
  const visible = useMemo(() => filterScans(feed.items, filters), [feed.items, filters])
  const mode = FEED_MODE[feed.mode] || FEED_MODE.connecting

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-xl font-semibold text-[color:var(--c2-fg-strong)]">
          <Activity className="h-5 w-5 text-[color:var(--c2-accent)]" aria-hidden="true" /> Live Threat Feed
        </h2>
        <SegmentedControl
          label="Counter window"
          value={period}
          onChange={setPeriod}
          options={[
            { value: '24h', label: 'Last 24 h' },
            { value: '7d', label: 'Last 7 d' },
          ]}
        />
      </div>
      <Stats demo={demo} period={period} />

      <Panel
        title="Finished scans"
        icon={Radio}
        actions={
          <Chip tone={mode.tone}>
            <span className={`h-1.5 w-1.5 rounded-full ${feed.mode === 'live' ? 'bg-[color:var(--c2-ok-dot)]' : 'bg-current'}`} aria-hidden="true" />
            {mode.text}
          </Chip>
        }
      >
        <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
          <ScanFilters filters={filters} onChange={setFilters} idPrefix="c2-feed" />
          <p className="text-xs text-[color:var(--c2-fg-muted)]" aria-live="polite">
            {visible.length} of {feed.items.length} shown
          </p>
        </div>
        {feed.mode === 'error' ? (
          <StateBox state="error" message={feed.error?.message}>
            <p className="text-xs text-[color:var(--c2-fg-muted)]">Switch on Demo mode to show the recorded feed.</p>
          </StateBox>
        ) : feed.mode === 'connecting' && !feed.items.length ? (
          <StateBox state="loading" message="Connecting to the live feed…" />
        ) : visible.length ? (
          <ScanTable items={visible} highlightIds={feed.freshIds} compact />
        ) : (
          <StateBox
            state="empty"
            message={
              feed.items.length
                ? 'No scan matches these filters.'
                : 'No scans yet. ThreatRadar pushes and user checks appear here the moment C2 finishes them.'
            }
          />
        )}
        {feed.error && feed.mode !== 'error' && <p className="mt-2 text-xs text-[color:var(--c2-sus)]">Last refresh failed: {feed.error.message}</p>}
      </Panel>
    </div>
  )
}
