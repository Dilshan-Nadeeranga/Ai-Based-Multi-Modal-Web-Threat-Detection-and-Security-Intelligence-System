import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { generateRemediation, listRemediations } from '../api/codeAuditApi.js'
import PatchValidation, { ValidationBadge } from './PatchValidation.jsx'

/**
 * Read-only AI remediation suggestion for one finding, with its static patch validation.
 * Suggestions are never applied; the analyst decides on the HITL review page.
 */
export default function RemediationSuggestion({ findingId }) {
  const [suggestion, setSuggestion] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    let active = true
    listRemediations(findingId)
      .then((records) => {
        const latest = records.find((record) => record.status === 'GENERATED')
        if (active && latest) setSuggestion(latest)
      })
      .catch(() => {})
    return () => {
      active = false
    }
  }, [findingId])

  async function handleGenerate() {
    setLoading(true)
    setError(null)
    try {
      setSuggestion(await generateRemediation(findingId))
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  function handleValidated(validation) {
    setSuggestion((current) => ({
      ...current,
      validation_status: validation.status,
      validation_id: validation.validation_id,
    }))
  }

  const needsContext = suggestion && suggestion.remediation_status !== 'SUCCESS'

  return (
    <div className="ca-detail__section ca-remediation">
      <h4>AI-Generated Remediation Suggestion</h4>

      {!suggestion && (
        <button
          type="button"
          className="ca-form__button ca-remediation__button"
          onClick={handleGenerate}
          disabled={loading}
        >
          {loading ? 'Generating suggestion…' : 'Generate Remediation Suggestion'}
        </button>
      )}
      {error && <p className="ca-error">{error}</p>}

      {suggestion && (
        <>
          <div className="ca-remediation__meta">
            <div className="ca-remediation__status">
              <ValidationBadge status={suggestion.validation_status} />
              {suggestion.llm_confidence && (
                <span className="ca-badge ca-badge--confidence">
                  Model confidence: {suggestion.llm_confidence}
                </span>
              )}
              {suggestion.review_decision && (
                <span className="ca-remediation__review-state">
                  Decision: {suggestion.review_decision}
                </span>
              )}
            </div>
            <Link
              className="ca-form__button ca-remediation__review-btn"
              to={`/code-audit/remediations/${encodeURIComponent(suggestion.remediation_id)}/review`}
            >
              Open Analyst Review
            </Link>
          </div>

          <h5>Summary</h5>
          <p>{suggestion.summary}</p>

          <h5>Explanation</h5>
          <p>{suggestion.security_reason}</p>
          {suggestion.changes?.length > 0 && (
            <ul>{suggestion.changes.map((item) => <li key={item}>{item}</li>)}</ul>
          )}
          {suggestion.assumptions?.length > 0 && (
            <p className="ca-detail__note">Assumptions: {suggestion.assumptions.join('; ')}</p>
          )}
          {suggestion.remaining_risks?.length > 0 && (
            <p className="ca-detail__note">Remaining risks: {suggestion.remaining_risks.join('; ')}</p>
          )}

          {needsContext ? (
            <p className="ca-detail__note">
              The model could not produce a safe patch from the available context
              ({suggestion.remediation_status}).
            </p>
          ) : (
            <>
              <h5>Suggested Code</h5>
              <pre className="ca-detail__code">{suggestion.patched_code}</pre>
            </>
          )}
          {suggestion.unverified_references?.length > 0 && (
            <p className="ca-detail__note">
              Not confirmed in the repository context: {suggestion.unverified_references.join(', ')}
            </p>
          )}

          {!needsContext && (
            <PatchValidation
              key={suggestion.remediation_id}
              remediation={suggestion}
              onValidated={handleValidated}
            />
          )}

          <div className="ca-remediation__note" role="note">
            <span className="ca-remediation__note-label">Note</span>
            <p>
              AI-generated remediation suggestion. It has not been applied to the repository.
            </p>
          </div>
        </>
      )}
    </div>
  )
}
