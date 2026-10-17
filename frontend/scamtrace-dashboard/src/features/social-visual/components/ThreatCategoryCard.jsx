import { ShieldCheck, ShieldX, Tags } from 'lucide-react'
import { pct } from './constants.js'
import { Card, NotAvailable } from './ui.jsx'

const SOURCE_STYLES = {
  model: 'bg-st-fixed text-st-navy',
  'model + rules': 'bg-st-container text-st-blue-dark',
  rules: 'bg-st-low text-st-muted',
}

function barColour(category) {
  if (category.category === 'LEGITIMATE') return 'bg-emerald-500'
  return category.detected ? 'bg-red-500' : 'bg-st-fixed-dim'
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
  const legit = classification.primary === 'LEGITIMATE'
  const PrimaryIcon = legit ? ShieldCheck : ShieldX
  const primaryScore = classification.categories.find((c) => c.category === classification.primary)?.score
  const also = classification.detected.filter((d) => d.category !== classification.primary)

  return (
    <Card title="Threat category" subtitle={subtitle} icon={Tags}>
      <div className="flex flex-wrap items-center gap-4 rounded-lg bg-st-low p-4 ring-1 ring-st-container">
        <span className={`st-pop flex h-12 w-12 items-center justify-center rounded-xl ${legit ? 'bg-emerald-100 text-emerald-700' : 'bg-red-100 text-red-700'}`}>
          <PrimaryIcon className="h-6 w-6" aria-hidden="true" />
        </span>
        <div>
          <p className="text-[11px] uppercase tracking-wide text-st-muted">Primary category</p>
          <p className={`font-manrope text-xl font-bold ${legit ? 'text-emerald-700' : 'text-red-700'}`}>
            {classification.primary_label || 'Not available'}
            {primaryScore !== undefined && primaryScore !== null && (
              <span className="ml-2 font-mono text-sm font-semibold text-st-muted">{pct(primaryScore)}</span>
            )}
          </p>
        </div>
        {also.length > 0 && (
          <div className="flex flex-wrap items-center gap-2 sm:ml-auto">
            <span className="text-[11px] uppercase tracking-wide text-st-muted">Also detected</span>
            {also.map((d) => (
              <span key={d.category} className="st-pop rounded-full bg-white px-3 py-1 text-xs font-semibold text-red-700 ring-1 ring-red-200">
                {d.label} <span className="font-mono">{pct(d.score)}</span>
              </span>
            ))}
          </div>
        )}
      </div>

      <ul className="st-stagger mt-4 space-y-1">
        {classification.categories.map((c) => {
          const width = c.score === null ? 0 : Math.max(0, Math.min(1, c.score)) * 100
          return (
            <li key={c.category} className={`rounded-lg px-3 py-2 transition-colors hover:bg-st-low ${c.detected ? 'bg-st-low/70' : ''}`}>
              <div className="flex items-center gap-3 text-sm">
                <span className={`w-40 shrink-0 ${c.detected ? 'font-semibold text-st-ink' : 'text-st-muted'}`}>{c.label}</span>
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-st-container">
                  <div className={`st-bar h-full rounded-full ${barColour(c)}`} style={{ width: `${width}%` }} />
                </div>
                <span className={`w-12 text-right font-mono text-xs ${c.detected ? 'font-semibold text-st-ink' : 'text-st-muted'}`}>
                  {c.score === null ? '—' : pct(c.score)}
                </span>
                <span className={`hidden w-24 shrink-0 rounded-full px-2 py-0.5 text-center text-[10px] font-semibold sm:inline ${SOURCE_STYLES[c.source]}`}>
                  {c.source}
                </span>
              </div>
              {c.evidence.length > 0 && (
                <p className="mt-1 break-words text-[11px] text-st-muted sm:pl-[10.75rem]">{c.evidence.join(' · ')}</p>
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
