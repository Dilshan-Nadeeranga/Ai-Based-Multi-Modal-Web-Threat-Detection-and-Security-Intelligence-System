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
        <circle cx="60" cy="60" r={radius} fill="none" stroke="var(--c2-gauge-track)" strokeWidth="10" />
        {value !== null && (
          <circle
            cx="60"
            cy="60"
            r={radius}
            fill="none"
            stroke="currentColor"
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={`${(value / 100) * circumference} ${circumference}`}
            transform="rotate(-90 60 60)"
            className="c2-gauge-arc"
            style={{ color }}
          />
        )}
        {tick(thresholds?.suspicious_min_risk, 'var(--c2-sus-solid)')}
        {tick(thresholds?.malicious_min_risk, 'var(--c2-mal-solid)')}
        <text x="60" y="58" textAnchor="middle" className="font-mono" fill="var(--c2-fg-strong)" fontSize="30" fontWeight="700">
          {value === null ? '—' : value}
        </text>
        <text x="60" y="78" textAnchor="middle" className="font-mono" fill="var(--c2-fg-muted)" fontSize="9" letterSpacing="2">
          RISK / 100
        </text>
      </svg>
      {thresholds?.suspicious_min_risk !== undefined && (
        <figcaption className="font-mono text-[0.6875rem] text-[color:var(--c2-fg-muted)]">
          <span className="text-[color:var(--c2-sus)]">▮</span> Suspicious ≥ {thresholds.suspicious_min_risk} ·{' '}
          <span className="text-[color:var(--c2-mal)]">▮</span> Malicious ≥ {thresholds.malicious_min_risk}
        </figcaption>
      )}
    </figure>
  )
}
