import { AlertTriangle, GitCompare } from 'lucide-react'
import { Card } from './ui.jsx'

const STATUS = {
  consistent: { label: 'CONSISTENT', className: 'bg-emerald-900/60 text-emerald-300 border-emerald-700' },
  match: { label: 'MATCH', className: 'bg-emerald-900/60 text-emerald-300 border-emerald-700' },
  inconsistent: { label: 'INCONSISTENT', className: 'bg-orange-900/60 text-orange-300 border-orange-700' },
  mismatch: { label: 'MISMATCH', className: 'bg-red-900/60 text-red-300 border-red-700' },
  not_available: { label: 'N/A', className: 'bg-slate-800 text-slate-400 border-slate-700' },
}
const SEVERITY = { high: 'text-red-400', medium: 'text-orange-400', low: 'text-amber-300' }

export default function ConsistencyAnalysis({ consistency }) {
  if (!consistency) return null
  const mismatch = consistency.brand_identity_mismatch
  return (
    <Card title="Cross-source consistency analysis" subtitle="Does the post's text, image, brand and destination tell the same story?"
          icon={GitCompare} className="border-sky-900/70 lg:p-8">
      {mismatch.detected && (
        <div className="mb-5 flex items-start gap-3 rounded-lg border border-red-700 bg-red-950/50 p-4">
          <AlertTriangle className="w-6 h-6 text-red-400 shrink-0" />
          <div>
            <p className="font-bold text-red-300">BRAND IDENTITY MISMATCH ({mismatch.strength})</p>
            <p className="text-sm text-red-200/80">{mismatch.reasons.join(', ')}</p>
          </div>
        </div>
      )}

      <div className="grid sm:grid-cols-3 gap-4 mb-5 text-sm">
        {[['Post brand', consistency.post_brand], ['Visual brand', consistency.visual_brand], ['Website brand', consistency.website_brand]].map(([label, brand]) => (
          <div key={label} className="rounded-lg bg-slate-950/60 border border-slate-800 p-3">
            <p className="text-[11px] uppercase text-slate-500">{label}</p>
            <p className="font-semibold text-slate-100">{brand ? (brand.name || brand.brand_id) : '—'}</p>
            <p className="text-[11px] text-slate-500">{brand ? (brand.origin || brand.method) : 'not identified'}</p>
          </div>
        ))}
      </div>

      <ul className="divide-y divide-slate-800 rounded-lg border border-slate-800">
        {consistency.comparisons.map((row) => {
          const status = STATUS[row.status] || STATUS.not_available
          return (
            <li key={row.key} className="flex flex-wrap items-center gap-3 px-4 py-3">
              <span className="flex-1 min-w-48 text-sm font-medium text-slate-200">{row.label}</span>
              <span className="text-xs font-mono text-slate-400">{row.display || ''}</span>
              <span className={`w-28 text-center rounded border px-2 py-0.5 text-xs font-bold ${status.className}`}>{status.label}</span>
            </li>
          )
        })}
      </ul>

      {consistency.flags.length > 0 && (
        <div className="mt-5">
          <p className="text-[11px] uppercase tracking-wide text-slate-500 mb-2">Flags</p>
          <ul className="space-y-1 text-sm">
            {consistency.flags.map((flag) => (
              <li key={flag.code}>
                <span className={`font-mono text-xs font-semibold ${SEVERITY[flag.severity]}`}>[{flag.severity}] {flag.code}</span>
                <span className="text-slate-300"> — {flag.detail}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Card>
  )
}
