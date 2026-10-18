import { VERDICT_STYLE } from '../constants.js'

/**
 * Circular 0–100 risk gauge (risk = round(100 × (1 − P(benign)))). Tick marks show where the
 * Suspicious / Malicious tiers start for the arm subset that was used (from explanation.thresholds).
 */
export default function RiskGauge({ score, verdict, thresholds, size = 148 }) {
  const radius = 54
  const circumference = 2 * Math.PI * radius
  const value = typeof score === 'number' ? Math.max(0, Math.min(100, score)) : null
  const color = (VERDICT_STYLE[verdict] || VERDICT_STYLE.none).hex
  const tick = (risk, tone) => {
    if (typeof risk !== 'number') return null
    const angle = (risk / 100) * 2 * Math.PI - Math.PI / 2
    const inner = radius - 9
    const outer = radius + 9
    return (
      <line
        key={risk}
        x1={60 + inner * Math.cos(angle)}
        y1={60 + inner * Math.sin(angle)}
        x2={60 + outer * Math.cos(angle)}
        y2={60 + outer * Math.sin(angle)}
        stroke={tone}
        strokeWidth="2"
      />
    )
  }
  const label = value === null ? 'No risk score' : `Risk score ${value} out of 100`
  return (
    <figure className="flex flex-col items-center gap-1" aria-label={label}>
      <svg width={size} height={size} viewBox="0 0 120 120" role="img" aria-label={label}>
        <circle cx="60" cy="60" r={radius} fill="none" stroke="#1e293b" strokeWidth="10" />
        {value !== null && (
          <circle
            cx="60"
            cy="60"
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={`${(value / 100) * circumference} ${circumference}`}
            transform="rotate(-90 60 60)"
            style={{ filter: `drop-shadow(0 0 4px ${color}66)` }}
          />
        )}
        {tick(thresholds?.suspicious_min_risk, '#fbbf24')}
        {tick(thresholds?.malicious_min_risk, '#f87171')}
        <text x="60" y="58" textAnchor="middle" className="fill-slate-50 font-mono" fontSize="30" fontWeight="700">
          {value === null ? '—' : value}
        </text>
        <text x="60" y="78" textAnchor="middle" className="fill-slate-400 font-mono" fontSize="9" letterSpacing="2">
          RISK / 100
        </text>
      </svg>
      {thresholds?.suspicious_min_risk !== undefined && (
        <figcaption className="font-mono text-[0.6875rem] text-slate-400">
          <span className="text-amber-300">▮</span> Suspicious ≥ {thresholds.suspicious_min_risk} ·{' '}
          <span className="text-red-300">▮</span> Malicious ≥ {thresholds.malicious_min_risk}
        </figcaption>
      )}
    </figure>
  )
}
