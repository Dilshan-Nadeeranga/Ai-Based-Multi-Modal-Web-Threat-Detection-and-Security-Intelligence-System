import { useState } from 'react'
import { generateRemediation } from '../api/codeAuditApi.js'

/**
 * Read-only AI remediation suggestion for one finding.
 * Suggestions are never applied; review/accept workflows come in a later phase.
 */
export default function RemediationSuggestion({ findingId }) {
  const [suggestion, setSuggestion] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

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
          <p className="ca-remediation__status">
            <span className="ca-badge ca-badge--unvalidated">Not Yet Validated</span>
            <span>Status: UNVALIDATED</span>
            {suggestion.llm_confidence && <span>Model confidence: {suggestion.llm_confidence}</span>}
          </p>

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
          <p className="ca-detail__note">
            AI-generated remediation suggestion — not yet validated. It has not been applied
            to the repository.
          </p>
        </>
      )}
    </div>
  )
}
