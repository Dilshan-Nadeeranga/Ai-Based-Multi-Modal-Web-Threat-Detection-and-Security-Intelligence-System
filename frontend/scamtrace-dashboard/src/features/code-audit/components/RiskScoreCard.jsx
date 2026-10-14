import HealthScore from './HealthScore.jsx'

const BAND_LABELS = {
  LOW: 'Low',
  MODERATE: 'Moderate',
  HIGH: 'High',
  VERY_HIGH: 'Very high',
}

const SEVERITIES = ['critical', 'high', 'medium', 'low']

export function RiskBand({ band }) {
  return (
    <span className={`ca-risk__band ca-risk__band--${band.toLowerCase().replace('_', '-')}`}>
      {BAND_LABELS[band] || band}
    </span>
  )
}

function SeverityCounts({ counts }) {
  return (
    <ul className="ca-risk__severities">
      {SEVERITIES.map((severity) => (
        <li key={severity} className={`ca-risk__sev ca-risk__sev--${severity}`}>
          <span>{severity}</span> {counts[severity] ?? 0}
        </li>
      ))}
    </ul>
  )
}

/** One side of the comparison: BEFORE-REMEDIATION or PROJECTED AFTER-REMEDIATION. */
export default function RiskScoreCard({ snapshot, detailed = false }) {
  const { label, preliminary_risk_score: risk, risk_band: band } = snapshot
  return (
    <article className="ca-risk__card">
      <h3 className="ca-risk__card-title">{label}</h3>
      <p className="ca-risk__score">
        {risk.toFixed(2)}<span>/100</span>
      </p>
      <p className="ca-risk__unit">preliminary internal risk index</p>
      <RiskBand band={band} />

      <dl className="ca-risk__facts">
        {detailed && (
          <>
            <div>
              <dt>Weighted vulnerability score</dt>
              <dd>{snapshot.weighted_vulnerability_score.toFixed(2)}/100</dd>
            </div>
            <div>
              <dt>Code health</dt>
              <dd>
                <HealthScore score={snapshot.code_health_score} label={snapshot.code_health_label} />
              </dd>
            </div>
          </>
        )}
        <div>
          <dt>Unresolved findings</dt>
          <dd>
            {snapshot.unresolved_findings}/{snapshot.total_security_findings}
            {snapshot.total_security_findings > 0 && ` (${snapshot.unresolved_rate.toFixed(0)}%)`}
          </dd>
        </div>
      </dl>
      <SeverityCounts counts={detailed ? snapshot.severity_counts : snapshot.unresolved_by_severity} />
    </article>
  )
}
