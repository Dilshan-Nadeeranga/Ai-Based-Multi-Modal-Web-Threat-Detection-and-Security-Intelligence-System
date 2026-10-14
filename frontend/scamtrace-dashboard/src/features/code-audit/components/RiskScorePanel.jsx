import { useEffect, useState } from 'react'
import { getRiskScore, recalculateRiskScore } from '../api/codeAuditApi.js'
import RiskScoreCard from './RiskScoreCard.jsx'

const REASONS = {
  NO_REMEDIATION: 'No remediation generated',
  GENERATION_FAILED: 'Generation failed / no candidate patch',
  NOT_VALIDATED: 'Not validated',
  VALIDATION_FAILED: 'Validation failed',
  VALIDATION_ERROR: 'Validation error',
  ANALYST_REJECTED: 'Rejected by analyst',
  NO_ANALYST_DECISION: 'No analyst decision',
}

function Disclaimer({ model }) {
  return (
    <div className="ca-risk__disclaimer" role="note">
      <strong>Preliminary Research Model</strong>
      {model && ` · ${model.model_name} v${model.model_version} · ${model.status} · not validated`}
      <p>
        This score is an experimental repository-level risk indicator for PP1. It is not a CVSS
        score, exploit probability, or validated industry-standard metric. Projected results assume
        validated and analyst-accepted remediation candidates are subsequently applied.
      </p>
    </div>
  )
}

function Reduction({ value }) {
  const lower = value > 0
  const text = value === 0
    ? 'No projected change'
    : `${Math.abs(value).toFixed(2)} points ${lower ? 'lower' : 'higher'} than before remediation`
  return (
    <article className="ca-risk__card ca-risk__card--reduction">
      <h3 className="ca-risk__card-title">Projected Risk Reduction</h3>
      <p className={`ca-risk__score ${lower ? 'ca-risk__score--down' : ''}`}>
        {value > 0 ? '−' : value < 0 ? '+' : ''}{Math.abs(value).toFixed(2)}<span> pts</span>
      </p>
      <p className="ca-risk__unit">{text}</p>
      <p className="ca-detail__note">Before − projected after, on the 0–100 index.</p>
    </article>
  )
}

/** Remount per scan so no assessment leaks between scans. */
export default function RiskScorePanel({ scanId }) {
  if (!scanId) return null
  return <RiskScoreView key={scanId} scanId={scanId} />
}

function RiskScoreView({ scanId }) {
  const [assessment, setAssessment] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let active = true
    getRiskScore(scanId)
      .then((data) => active && setAssessment(data))
      .catch((err) => active && setError(err.message))
    return () => {
      active = false
    }
  }, [scanId])

  async function handleRecalculate() {
    setBusy(true)
    setError(null)
    try {
      setAssessment(await recalculateRiskScore(scanId))
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  if (!assessment) {
    return (
      <section className="ca-summary ca-risk">
        <h2 className="ca-summary__title">Preliminary Risk / Exploitability Score</h2>
        {error ? (
          <p className="ca-error ca-error--server">Score unavailable. {error}</p>
        ) : (
          <p className="ca-loading">Calculating preliminary risk score…</p>
        )}
        <Disclaimer />
      </section>
    )
  }

  const { before, projected_after: after, breakdown, model } = assessment
  const reasons = Object.entries(breakdown.unresolved_reasons)

  return (
    <section className="ca-summary ca-risk">
      <h2 className="ca-summary__title">Preliminary Risk / Exploitability Score</h2>
      <Disclaimer model={model} />

      {before.total_security_findings === 0 && (
        <p className="ca-empty">
          No scored security findings for this scan — the index reflects code health only.
        </p>
      )}
      {assessment.assessment_completeness === 'PARTIAL' && (
        <p className="ca-review__warning" role="status">
          Partial assessment: code health is unavailable because AST analysis did not complete.
          Weights were renormalized (vulnerability 60/85, unresolved 25/85); no code-health value
          was assumed.
        </p>
      )}

      <div className="ca-risk__cards">
        <RiskScoreCard snapshot={before} detailed />
        <RiskScoreCard snapshot={after} />
        <Reduction value={assessment.projected_risk_reduction} />
      </div>

      <p className="ca-detail__note">
        PROJECTED AFTER-REMEDIATION removes only findings whose candidate patch passed validation
        (PASSED or PASSED_WITH_WARNINGS) and was ACCEPTED by an analyst. Nothing has been applied to
        the repository; code health is kept unchanged.
      </p>

      <details className="ca-risk__breakdown">
        <summary>
          Breakdown — {breakdown.projected_resolved} projected resolved, {breakdown.unresolved} unresolved
        </summary>
        {reasons.length > 0 && (
          <ul className="ca-validation__issues">
            {reasons.map(([reason, count]) => (
              <li key={reason}>{REASONS[reason] || reason}: {count}</li>
            ))}
          </ul>
        )}
        <p className="ca-detail__note">
          Scored security findings: {breakdown.security_findings} · informational findings excluded:{' '}
          {breakdown.info_findings_excluded} · code-quality findings: {breakdown.quality_findings}{' '}
          (long methods {breakdown.quality_issue_counts.LONG_METHOD ?? 0}, large files{' '}
          {breakdown.quality_issue_counts.LARGE_FILE ?? 0})
        </p>
        <p className="ca-detail__note">
          Assessment <code>{assessment.assessment_id}</code> · calculated{' '}
          {new Date(assessment.calculated_at).toLocaleString()} · formula: {assessment.assumptions_reference}
        </p>
      </details>

      <button type="button" className="ca-form__button ca-risk__recalculate"
              onClick={handleRecalculate} disabled={busy}>
        {busy ? 'Recalculating…' : 'Recalculate'}
      </button>
      {error && <p className="ca-error">{error}</p>}
    </section>
  )
}
