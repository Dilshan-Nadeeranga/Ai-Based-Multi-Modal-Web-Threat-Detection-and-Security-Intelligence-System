import { AlertTriangle, GitCompare } from 'lucide-react'
import { Card } from './ui.jsx'

const STATUS = {
  consistent: { label: 'CONSISTENT', className: 'bg-emerald-100 text-emerald-700 border-emerald-200' },
  match: { label: 'MATCH', className: 'bg-emerald-100 text-emerald-700 border-emerald-200' },
  inconsistent: { label: 'INCONSISTENT', className: 'bg-orange-100 text-orange-700 border-orange-200' },
  mismatch: { label: 'MISMATCH', className: 'bg-red-100 text-red-700 border-red-200' },
  not_available: { label: 'N/A', className: 'bg-st-container text-st-muted border-st-container' },
}
const SEVERITY = { high: 'text-red-700', medium: 'text-orange-700', low: 'text-amber-700' }

export default function ConsistencyAnalysis({ consistency }) {
  if (!consistency) return null
  const mismatch = consistency.brand_identity_mismatch
  return (
    <Card title="Cross-source consistency analysis" subtitle="Does the post's text, image, brand and destination tell the same story?"
          icon={GitCompare} className="border-st-fixed lg:p-8">
      {mismatch.detected && (
        <div className="mb-5 flex items-start gap-3 rounded-lg border border-red-200 bg-red-50 p-4">
          <AlertTriangle className="w-6 h-6 text-red-700 shrink-0" />
          <div>
            <p className="font-bold text-red-700">BRAND IDENTITY MISMATCH ({mismatch.strength})</p>
            <p className="text-sm text-red-800">{mismatch.reasons.join(', ')}</p>
          </div>
        </div>
      )}

      <div className="grid sm:grid-cols-3 gap-4 mb-5 text-sm">
        {[['Post brand', consistency.post_brand], ['Visual brand', consistency.visual_brand], ['Website brand', consistency.website_brand]].map(([label, brand]) => (
          <div key={label} className="rounded-lg bg-st-low border border-st-container p-3">
            <p className="text-[11px] uppercase text-st-muted">{label}</p>
            <p className="font-semibold text-st-ink">{brand ? (brand.name || brand.brand_id) : '—'}</p>
            <p className="text-[11px] text-st-muted">{brand ? (brand.origin || brand.method) : 'not identified'}</p>
          </div>
        ))}
      </div>

      <ul className="divide-y divide-st-container rounded-lg border border-st-container">
        {consistency.comparisons.map((row) => {
          const status = STATUS[row.status] || STATUS.not_available
          return (
            <li key={row.key} className="flex flex-wrap items-center gap-3 px-4 py-3">
              <span className="flex-1 min-w-48 text-sm font-medium text-st-ink">{row.label}</span>
              <span className="text-xs font-mono text-st-muted">{row.display || ''}</span>
              <span className={`w-28 text-center rounded border px-2 py-0.5 text-xs font-bold ${status.className}`}>{status.label}</span>
            </li>
          )
        })}
      </ul>

      {consistency.flags.length > 0 && (
        <div className="mt-5">
          <p className="text-[11px] uppercase tracking-wide text-st-muted mb-2">Flags</p>
          <ul className="space-y-1 text-sm">
            {consistency.flags.map((flag) => (
              <li key={flag.code}>
                <span className={`font-mono text-xs font-semibold ${SEVERITY[flag.severity]}`}>[{flag.severity}] {flag.code}</span>
                <span className="text-st-ink"> — {flag.detail}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Card>
  )
}
