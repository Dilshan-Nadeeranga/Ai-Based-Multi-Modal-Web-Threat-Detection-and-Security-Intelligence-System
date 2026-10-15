import { Tags } from 'lucide-react'
import { pct } from './constants.js'
import { Card, NotAvailable } from './ui.jsx'

const SOURCE_STYLES = {
  model: 'border-st-fixed text-st-blue-dark',
  'model + rules': 'border-indigo-200 text-indigo-700',
  rules: 'border-st-container text-st-muted',
}

export default function ThreatCategoryCard({ classification }) {
  if (!classification) {
    return (
      <Card title="Threat category" icon={Tags}>
        <NotAvailable>Threat classification did not run.</NotAvailable>
      </Card>
    )
  }
  const { models = {} } = classification
  const subtitle = [
    models.category || 'Category text model not trained',
    models.misinformation || 'misinformation model not trained',
    'evidence rules',
  ].join(' · ')

  return (
    <Card title="Threat category" subtitle={subtitle} icon={Tags}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs uppercase text-st-muted">Primary</span>
        <span className={`rounded px-2 py-0.5 text-sm font-semibold ${classification.primary === 'LEGITIMATE'
          ? 'bg-emerald-50 text-emerald-700' : 'bg-red-50 text-red-700'}`}>
          {classification.primary || 'NOT AVAILABLE'}
        </span>
        {classification.detected.filter((d) => d.category !== classification.primary).map((d) => (
          <span key={d.category} className="rounded bg-orange-50 px-2 py-0.5 text-xs text-orange-700">
            also {d.category} {pct(d.score)}
          </span>
        ))}
      </div>

      <ul className="mt-4 divide-y divide-st-container">
        {classification.categories.map((c) => {
          const width = c.score === null ? 0 : Math.max(0, Math.min(1, c.score)) * 100
          const colour = c.category === 'LEGITIMATE' ? 'bg-emerald-500' : c.detected ? 'bg-red-500' : 'bg-st-outline'
          return (
            <li key={c.category} className="py-2">
              <div className="flex items-center gap-3 text-xs">
                <span className={`w-44 shrink-0 font-mono ${c.detected ? 'text-st-ink font-semibold' : 'text-st-muted'}`}>
                  {c.category}
                </span>
                <div className="h-2 flex-1 rounded bg-st-container overflow-hidden">
                  <div className={`h-full ${colour}`} style={{ width: `${width}%` }} />
                </div>
                <span className="w-12 text-right font-mono text-st-ink">{c.score === null ? '—' : pct(c.score)}</span>
                <span className={`hidden sm:inline w-24 shrink-0 rounded border px-1.5 text-center text-[10px] ${SOURCE_STYLES[c.source]}`}>
                  {c.source}
                </span>
              </div>
              {c.evidence.length > 0 && (
                <p className="mt-1 pl-0 sm:pl-[11.75rem] text-[11px] text-st-muted break-words">{c.evidence.join('; ')}</p>
              )}
            </li>
          )
        })}
      </ul>
      <p className="mt-3 text-[11px] text-st-muted">
        A category is detected at a score of {pct(classification.threshold)} or more. Brand impersonation, malware, browser abuse
        and other scam have no labelled training samples and come from pipeline evidence; scores are indicators, not calibrated
        probabilities.
      </p>
    </Card>
  )
}
