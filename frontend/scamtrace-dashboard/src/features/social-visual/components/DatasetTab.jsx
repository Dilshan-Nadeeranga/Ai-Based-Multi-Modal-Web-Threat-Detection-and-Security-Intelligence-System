import { useEffect, useState } from 'react'
import { Database, Loader2 } from 'lucide-react'
import { getDatasetStatistics } from '../api/socialVisualApi.js'
import { Card } from './ui.jsx'

function Distribution({ title, data }) {
  const entries = Object.entries(data || {}).filter(([, value]) => typeof value === 'number' && value > 0)
  const max = Math.max(1, ...entries.map(([, value]) => value))
  return (
    <Card title={title}>
      <div className="space-y-2">
        {entries.map(([key, value]) => (
          <div key={key}>
            <div className="flex justify-between text-xs text-st-ink"><span>{key.replaceAll('_', ' ')}</span><span className="font-mono">{value}</span></div>
            <div className="mt-1 h-2 rounded bg-st-container overflow-hidden"><div className="h-full bg-sky-500" style={{ width: `${(value / max) * 100}%` }} /></div>
          </div>
        ))}
        {entries.length === 0 && <p className="text-sm text-st-muted">No data.</p>}
      </div>
    </Card>
  )
}

export default function DatasetTab() {
  const [stats, setStats] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    getDatasetStatistics().then(setStats).catch((err) => setError(err.message))
  }, [])

  if (error) return <p role="alert" className="rounded-lg bg-st-error-bg p-4 text-sm text-st-error-ink">{error}</p>
  if (!stats) return <p className="flex items-center gap-2 text-sm text-st-muted"><Loader2 className="w-4 h-4 animate-spin" /> Loading dataset statistics…</p>

  const totals = [
    ['Samples', stats.total_samples], ['Verified labels', stats.label_status?.verified],
    ['Images', stats.total_images], ['Embedded URLs', stats.total_embedded_urls],
    ['Samples with text', stats.samples_with_text], ['Web captures', stats.web_captures?.captured],
  ]
  return (
    <div className="space-y-6">
      <Card title="C3 multimodal dataset" subtitle={`Version ${stats.dataset_version} · generated ${stats.generated_at}`} icon={Database}>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
          {totals.map(([label, value]) => (
            <div key={label} className="rounded-lg bg-st-low border border-st-container p-3">
              <p className="text-[11px] uppercase text-st-muted">{label}</p>
              <p className="text-xl font-bold text-st-ink">{value ?? '—'}</p>
            </div>
          ))}
        </div>
      </Card>
      <div className="grid md:grid-cols-2 gap-6">
        <Distribution title="Binary labels" data={stats.binary_labels} />
        <Distribution title="Scam type" data={stats.class_distribution} />
        <Distribution title="Platform" data={stats.platform_distribution} />
        <Distribution title="Collection method" data={stats.collection_method_distribution} />
      </div>
    </div>
  )
}
