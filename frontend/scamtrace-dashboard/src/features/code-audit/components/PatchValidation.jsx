import { useEffect, useState } from 'react'
import { getValidation, validateRemediation } from '../api/codeAuditApi.js'
import DiffViewer from './DiffViewer.jsx'

const STATUS_LABELS = {
  NOT_VALIDATED: 'Not Validated',
  VALIDATING: 'Validating',
  PASSED: 'Passed',
  PASSED_WITH_WARNINGS: 'Passed with Warnings',
  FAILED: 'Failed',
  ERROR: 'Error',
}

const STATUS_BADGE = {
  NOT_VALIDATED: 'ca-badge--unvalidated',
  VALIDATING: 'ca-badge--unvalidated',
  PASSED: 'ca-badge--completed',
  PASSED_WITH_WARNINGS: 'ca-badge--warning',
  FAILED: 'ca-badge--failed',
  ERROR: 'ca-badge--failed',
}

const CHECK_LABELS = {
  PASS: 'PASS',
  FAIL: 'FAIL',
  WARNING: 'CHANGED',
  SKIPPED: 'Skipped',
  NOT_APPLICABLE: 'N/A',
  ERROR: 'ERROR',
  REMOVED: 'REMOVED',
  REMAINS: 'STILL PRESENT',
  NOT_REPRODUCED: 'NOT REPRODUCED',
  NOT_CHECKED: 'Not checked',
}

export function ValidationBadge({ status }) {
  const key = status || 'NOT_VALIDATED'
  return (
    <span className={`ca-badge ${STATUS_BADGE[key] || 'ca-badge--unvalidated'}`}>
      {STATUS_LABELS[key] || key}
    </span>
  )
}

/** Deterministic check table, failure reasons, warnings and new findings of one validation. */
export function ValidationChecks({ validation }) {
  const summary = validation.summary
  return (
    <>
      <table className="ca-validation__checks">
        <tbody>
          <tr><th>Syntax</th><td>{CHECK_LABELS[summary.syntax]}</td></tr>
          <tr><th>AST Parse</th><td>{CHECK_LABELS[summary.ast]}</td></tr>
          <tr><th>Function Signature</th><td>{CHECK_LABELS[summary.signature]}</td></tr>
          <tr><th>Original Finding ({validation.rule_id})</th><td>{CHECK_LABELS[summary.original_finding]}</td></tr>
          <tr><th>New Critical Findings</th><td>{summary.new_critical}</td></tr>
          <tr><th>New High Findings</th><td>{summary.new_high}</td></tr>
          <tr><th>Other New Findings</th><td>{summary.new_findings - summary.new_critical - summary.new_high}</td></tr>
          <tr><th>Validation Status</th><td><ValidationBadge status={validation.status} /></td></tr>
        </tbody>
      </table>

      {validation.failure_reasons.length > 0 && (
        <>
          <h5>{validation.status === 'ERROR' ? 'Validation Could Not Complete' : 'Validation Failed'}</h5>
          <ul className="ca-validation__issues">
            {validation.failure_reasons.map((issue) => (
              <li key={issue.code + issue.message}><strong>{issue.code}</strong>: {issue.message}</li>
            ))}
          </ul>
        </>
      )}
      {validation.warnings.length > 0 && (
        <>
          <h5>Warnings</h5>
          <ul className="ca-validation__issues">
            {validation.warnings.map((issue) => (
              <li key={issue.code + issue.message}><strong>{issue.code}</strong>: {issue.message}</li>
            ))}
          </ul>
        </>
      )}
      {validation.new_findings.length > 0 && (
        <>
          <h5>New Findings in Candidate</h5>
          <ul className="ca-validation__issues">
            {validation.new_findings.map((finding) => (
              <li key={`${finding.rule_id}-${finding.line}`}>
                {finding.severity} — {finding.title} ({finding.rule_id}, candidate line {finding.line})
              </li>
            ))}
          </ul>
        </>
      )}
      {validation.syntax_validation.errors.length > 0 && (
        <p className="ca-detail__note">
          Syntax errors at candidate line(s):{' '}
          {validation.syntax_validation.errors.map((e) => e.line).join(', ')}
        </p>
      )}
    </>
  )
}

/**
 * Deterministic static validation of an AI remediation candidate.
 * Shows check results and the unified diff; never applies or approves the patch.
 */
export default function PatchValidation({ remediation, onValidated }) {
  const [validation, setValidation] = useState(null)
  const [validating, setValidating] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!remediation.validation_id) return
    let active = true
    getValidation(remediation.validation_id)
      .then((result) => active && setValidation(result))
      .catch(() => {})
    return () => {
      active = false
    }
  }, [remediation.validation_id])

  async function handleValidate() {
    setValidating(true)
    setError(null)
    try {
      const result = await validateRemediation(remediation.remediation_id)
      setValidation(result)
      onValidated?.(result)
    } catch (err) {
      setError(err.message)
    } finally {
      setValidating(false)
    }
  }

  const status = validating ? 'VALIDATING' : validation?.status || remediation.validation_status

  return (
    <div className="ca-validation">
      <h5>Patch Validation</h5>
      <p className="ca-remediation__status">
        <ValidationBadge status={status} />
        <button
          type="button"
          className="ca-form__button ca-remediation__button"
          onClick={handleValidate}
          disabled={validating}
        >
          {validating ? 'Running static checks…' : validation ? 'Re-run Validation' : 'Validate Patch'}
        </button>
      </p>
      {error && <p className="ca-error">{error}</p>}

      {validation && (
        <>
          <ValidationChecks validation={validation} />

          <h5>Original vs Suggested Patch</h5>
          <DiffViewer diff={validation.diff.diff} />

          <div className="ca-validation__stats">
            <span className="ca-validation__stat ca-validation__stat--add">
              +{validation.diff.added_lines} lines
            </span>
            <span className="ca-validation__stat ca-validation__stat--del">
              −{validation.diff.removed_lines} lines
            </span>
            <span className="ca-validation__stat">
              {validation.validation_duration_ms} ms
            </span>
            <span className="ca-validation__stat ca-validation__stat--id" title={validation.validation_id}>
              {validation.validation_id}
            </span>
          </div>

          {validation.note && (
            <div className="ca-remediation__note ca-validation__note" role="note">
              <span className="ca-remediation__note-label">Note</span>
              <p>{validation.note}</p>
            </div>
          )}
        </>
      )}
    </div>
  )
}
