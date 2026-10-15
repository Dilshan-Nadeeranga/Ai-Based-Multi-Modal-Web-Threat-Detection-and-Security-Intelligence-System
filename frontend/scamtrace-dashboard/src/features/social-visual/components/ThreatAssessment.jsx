import { ShieldAlert } from 'lucide-react'
import { LEVEL_STYLES, pct } from './constants.js'

export default function ThreatAssessment({ assessment, disclaimer }) {
  const style = LEVEL_STYLES[assessment.level] || LEVEL_STYLES.LOW
  const domainTone = assessment.domain_match === 'PASSED' ? 'text-emerald-700'
    : assessment.domain_match === 'FAILED' ? 'text-red-700' : 'text-st-muted'

  return (
    <section className={`rounded-xl border-2 ${style.border} ${style.soft} p-6`}>
      <p className="flex items-center gap-2 text-xs font-semibold uppercase tracking-widest text-st-ink">
        <ShieldAlert className="w-4 h-4" /> Preliminary threat assessment
      </p>
      <div className="mt-4 flex flex-wrap items-end gap-x-10 gap-y-4">
        <div>
          <p className={`text-5xl font-black tracking-tight ${style.text}`}>{assessment.level}</p>
          <p className="mt-1 text-sm text-st-muted">Risk score <span className={`font-mono font-semibold ${style.text}`}>{pct(assessment.score, 1)}</span></p>
        </div>
        <dl className="grid grid-cols-2 sm:grid-cols-3 gap-x-8 gap-y-3 text-sm">
          <div><dt className="text-[11px] uppercase text-st-muted">Detected threat</dt><dd className="font-semibold text-st-ink">{assessment.detected_threat}</dd></div>
          <div><dt className="text-[11px] uppercase text-st-muted">Detected brand</dt><dd className="font-semibold text-st-ink">{assessment.detected_brand || 'None identified'}</dd></div>
          <div><dt className="text-[11px] uppercase text-st-muted">Domain match</dt><dd className={`font-semibold ${domainTone}`}>{assessment.domain_match}</dd></div>
        </dl>
      </div>
      <div className="mt-4 h-2 rounded bg-st-container overflow-hidden">
        <div className={`h-full ${style.bg}`} style={{ width: `${(assessment.score || 0) * 100}%` }} />
      </div>
      <p className="mt-3 text-[11px] text-st-muted">{disclaimer} Threat label is {assessment.threat_rule}.</p>
    </section>
  )
}
