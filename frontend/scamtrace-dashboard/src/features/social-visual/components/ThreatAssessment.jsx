import { Fingerprint, Globe, ShieldAlert, Tag } from 'lucide-react'
import { LEVEL_STYLES, pct } from './constants.js'
import useCountUp from './useCountUp.js'

const RING = { LOW: '#10b981', MEDIUM: '#f97316', HIGH: '#ef4444' }
const RADIUS = 52
const CIRCUMFERENCE = 2 * Math.PI * RADIUS

function Gauge({ score, level, style }) {
  const value = useCountUp(score || 0)
  return (
    <div className="relative h-36 w-36 shrink-0">
      <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90">
        <circle cx="60" cy="60" r={RADIUS} fill="none" stroke="#ececff" strokeWidth="10" />
        <circle cx="60" cy="60" r={RADIUS} fill="none" stroke={RING[level] || RING.LOW} strokeWidth="10" strokeLinecap="round"
                strokeDasharray={CIRCUMFERENCE} strokeDashoffset={CIRCUMFERENCE * (1 - value)} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`font-manrope text-3xl font-black ${style.text}`}>{(value * 100).toFixed(1)}%</span>
        <span className="text-[10px] font-semibold uppercase tracking-wider text-st-muted">risk score</span>
      </div>
    </div>
  )
}

function Fact({ icon: Icon, label, children, tone = 'text-st-ink' }) {
  return (
    <div className="rounded-lg bg-white/70 p-3 ring-1 ring-black/5">
      <p className="flex items-center gap-1.5 text-[11px] uppercase tracking-wide text-st-muted">
        <Icon className="h-3.5 w-3.5" aria-hidden="true" /> {label}
      </p>
      <p className={`mt-1 font-semibold ${tone}`}>{children}</p>
    </div>
  )
}

export default function ThreatAssessment({ assessment, disclaimer }) {
  const style = LEVEL_STYLES[assessment.level] || LEVEL_STYLES.LOW
  const domainTone = assessment.domain_match === 'PASSED' ? 'text-emerald-700'
    : assessment.domain_match === 'FAILED' ? 'text-red-700' : 'text-st-muted'
  const others = (assessment.detected_categories || []).filter((d) => d.label !== assessment.detected_threat)

  return (
    <section className={`st-fade-up rounded-xl border-2 ${style.border} ${style.soft} p-6`}>
      <p className="flex items-center gap-2 text-xs font-semibold uppercase tracking-widest text-st-ink">
        <ShieldAlert className="w-4 h-4" aria-hidden="true" /> Preliminary threat assessment
      </p>
      <div className="mt-4 flex flex-col gap-6 md:flex-row md:items-center">
        <Gauge score={assessment.score} level={assessment.level} style={style} />
        <div className="flex-1 space-y-4">
          <div className="flex items-center gap-3">
            <span className="relative flex h-3 w-3">
              {assessment.level !== 'LOW' && <span className={`absolute inline-flex h-full w-full animate-ping rounded-full ${style.bg} opacity-60`} />}
              <span className={`relative inline-flex h-3 w-3 rounded-full ${style.bg}`} />
            </span>
            <p className={`st-pop font-manrope text-4xl font-black tracking-tight ${style.text}`}>{assessment.level}</p>
          </div>
          <div className="grid gap-3 sm:grid-cols-3">
            <Fact icon={Tag} label="Detected threat">{assessment.detected_threat}</Fact>
            <Fact icon={Fingerprint} label="Detected brand">{assessment.detected_brand || 'None identified'}</Fact>
            <Fact icon={Globe} label="Domain match" tone={domainTone}>{assessment.domain_match}</Fact>
          </div>
          {others.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[11px] uppercase tracking-wide text-st-muted">Also indicates</span>
              {others.map((d) => (
                <span key={d.category} className="st-pop rounded-full bg-white/80 px-3 py-1 text-xs font-semibold text-st-ink ring-1 ring-black/5">
                  {d.label} <span className="font-mono text-st-muted">{pct(d.score)}</span>
                </span>
              ))}
            </div>
          )}
        </div>
      </div>
      <p className="mt-5 text-[11px] text-st-muted">{disclaimer} Threat label is {assessment.threat_rule}.</p>
    </section>
  )
}
