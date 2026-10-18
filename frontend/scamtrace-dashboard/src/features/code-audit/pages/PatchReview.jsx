import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import AppShell from '../../../components/AppShell.jsx'
import { CODE_AUDIT_SECTION } from '../navigation.js'
import { getReviewWorkspace, startReview, validateRemediation } from '../api/codeAuditApi.js'
import CodeViewer from '../components/CodeViewer.jsx'
import DiffViewer from '../components/DiffViewer.jsx'
import PatchActions from '../components/PatchActions.jsx'
import { ValidationBadge, ValidationChecks } from '../components/PatchValidation.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'
import '../codeAudit.css'

const LOAD_ERRORS = {
  REMEDIATION_NOT_FOUND: 'This remediation suggestion does not exist.',
  FINDING_NOT_FOUND: 'The finding for this remediation no longer exists.',
  RELATION_MISMATCH: 'The stored finding, remediation and validation records do not match. Review is not possible.',
}

function ReviewPage({ children }) {
  return (
    <AppShell title="Analyst Review" section={CODE_AUDIT_SECTION}>
      <div className="ca-page ca-review">{children}</div>
    </AppShell>
  )
}

function Section({ letter, title, children }) {
  return (
    <section className="ca-detail ca-review__section">
      <h2 className="ca-review__heading">
        <span className="ca-review__letter">{letter}</span> {title}
      </h2>
      {children}
    </section>
  )
}

function List({ title, items, empty }) {
  return (
    <>
      <h5>{title}</h5>
      {items?.length ? (
        <ul className="ca-validation__issues">{items.map((item) => <li key={item}>{item}</li>)}</ul>
      ) : (
        <p className="ca-detail__note">{empty}</p>
      )}
    </>
  )
}

/** Route entry: remount per remediation so no review state leaks between reviews. */
export default function PatchReview() {
  const { remediationId } = useParams()
  return <AnalystReview key={remediationId || 'none'} remediationId={remediationId} />
}

/** HITL Analyst Review workspace for one AI remediation suggestion. */
function AnalystReview({ remediationId }) {
  const [workspace, setWorkspace] = useState(null)
  const [review, setReview] = useState(null)
  const [loadError, setLoadError] = useState(null)
  const [notice, setNotice] = useState(null)
  const [validating, setValidating] = useState(false)
  const [validationError, setValidationError] = useState(null)

  const fetchWorkspace = useCallback(async () => {
    const data = await getReviewWorkspace(remediationId)
    let current = data.review
    if (!current) {
      try {
        current = await startReview(remediationId)
      } catch {
        current = null // review still possible; duration will be unavailable
      }
    }
    return { data, current }
  }, [remediationId])

  useEffect(() => {
    if (!remediationId) return undefined
    let active = true
    fetchWorkspace()
      .then(({ data, current }) => {
        if (!active) return
        setWorkspace(data)
        setReview(current)
      })
      .catch((err) => {
        if (!active) return
        setLoadError(
          LOAD_ERRORS[err.code] ||
            (err.status === 0 ? err.message : 'Unable to load the analyst review. Please try again.')
        )
      })
    return () => {
      active = false
    }
  }, [remediationId, fetchWorkspace])

  async function handleValidate() {
    setValidating(true)
    setValidationError(null)
    try {
      await validateRemediation(remediationId)
      const { data, current } = await fetchWorkspace()
      setWorkspace(data)
      setReview(current)
    } catch (err) {
      setValidationError(err.message)
    } finally {
      setValidating(false)
    }
  }

  function handleDecided(saved, message = null) {
    setReview(saved)
    setNotice(message)
  }

  if (!remediationId) {
    return (
      <ReviewPage>
        <header className="ca-page__header"><h1>HITL Analyst Review</h1></header>
        <p className="ca-empty">
          Open a finding in the <Link to="/code-audit">Code Audit</Link> report and choose
          “Open Analyst Review” on its AI remediation suggestion.
        </p>
      </ReviewPage>
    )
  }
  if (loadError) {
    return (
      <ReviewPage>
        <header className="ca-page__header"><h1>HITL Analyst Review</h1></header>
        <p className="ca-error" role="alert">{loadError}</p>
        <Link to="/code-audit">Back to Code Audit</Link>
      </ReviewPage>
    )
  }
  if (!workspace) {
    return (
      <ReviewPage>
        <p className="ca-loading">Loading analyst review…</p>
      </ReviewPage>
    )
  }

  const { finding, remediation, validation, policy } = workspace
  const decided = review && review.decision !== 'PENDING'
  const location = finding.end_line && finding.end_line !== finding.start_line
    ? `${finding.start_line}–${finding.end_line}`
    : finding.start_line

  return (
    <ReviewPage>
      <header className="ca-page__header">
        <h1>HITL Analyst Review</h1>
        <p className="ca-page__subtitle">
          Mandatory human decision before patch approval. Review the deterministic evidence, then
          accept or reject the AI-generated suggestion.
        </p>
      </header>

      <Section letter="A" title="Vulnerability Details">
        <h3 className="ca-detail__title">{finding.title}</h3>
        <dl className="ca-detail__grid">
          <div>
            <dt>Severity</dt>
            <dd><SeverityBadge severity={finding.severity} /></dd>
          </div>
          <div>
            <dt>CWE</dt>
            <dd>{finding.cwe.length ? finding.cwe.join(', ') : 'Not assigned'}</dd>
          </div>
          <div>
            <dt>Category</dt>
            <dd>{finding.category || '—'}</dd>
          </div>
          <div>
            <dt>File</dt>
            <dd className="ca-detail__file">{finding.file_path}</dd>
          </div>
          <div>
            <dt>Line</dt>
            <dd>{location}</dd>
          </div>
          <div>
            <dt>Function</dt>
            <dd>{finding.function_name ? `${finding.function_name}()` : 'Not identified'}</dd>
          </div>
          <div>
            <dt>Rule</dt>
            <dd><code className="ca-detail__rule">{finding.rule_id}</code></dd>
          </div>
          <div>
            <dt>Validation</dt>
            <dd><ValidationBadge status={validation?.status || remediation.validation_status} /></dd>
          </div>
          <div>
            <dt>Status</dt>
            <dd>{decided ? `Analyst decision: ${review.decision}` : 'Awaiting Analyst Review'}</dd>
          </div>
        </dl>
        <h5>Description</h5>
        <p>{finding.description}</p>
      </Section>

      <Section letter="B" title="Original Code">
        <p className="ca-detail__note">
          {remediation.target_file}
          {remediation.original_start_line &&
            ` · lines ${remediation.original_start_line}–${remediation.original_end_line}`}{' '}
          · read-only · secrets masked
        </p>
        <CodeViewer code={remediation.original_code} startLine={remediation.original_start_line}
                    label="Original code" />
      </Section>

      <Section letter="C" title="AI-Generated Remediation Suggestion">
        <p className="ca-detail__note">
          Generated by {remediation.provider} / {remediation.model}
          {remediation.llm_confidence && ` · model confidence ${remediation.llm_confidence}`} ·{' '}
          {decided ? `analyst decision: ${review.decision}` : 'Awaiting Analyst Review'} · read-only
        </p>
        {remediation.patched_code ? (
          <CodeViewer code={remediation.patched_code} startLine={remediation.original_start_line}
                      label="AI-generated remediation suggestion" />
        ) : (
          <p className="ca-empty">
            No candidate patch was generated ({remediation.remediation_status || remediation.status}).
          </p>
        )}

        <h4 className="ca-review__subheading">Why was this remediation suggested?</h4>
        <h5>Summary</h5>
        <p>{remediation.summary || 'No summary provided.'}</p>
        <h5>Security Reason</h5>
        <p>{remediation.security_reason || 'No reason provided.'}</p>
        <List title="Changes" items={remediation.changes} empty="No changes listed." />
        <List title="Assumptions" items={remediation.assumptions} empty="None reported." />
        <List title="Remaining Risks" items={remediation.remaining_risks}
              empty="None reported by the remediation engine." />
        {remediation.unverified_references?.length > 0 && (
          <p className="ca-detail__note">
            Not confirmed in the repository context: {remediation.unverified_references.join(', ')}
          </p>
        )}
      </Section>

      <Section letter="D" title="Unified Diff (Original vs Suggested)">
        {validation ? (
          <>
            <p className="ca-detail__note">
              <span className="ca-diff__del">− removed (original)</span>{' '}
              <span className="ca-diff__add">+ added (suggested)</span> · from validation{' '}
              {validation.validation_id}
            </p>
            <DiffViewer diff={validation.diff.diff} />
          </>
        ) : (
          <p className="ca-empty">
            The unified diff is produced by Patch Validation. This candidate has not been validated yet.
          </p>
        )}
      </Section>

      <Section letter="E" title="Deterministic Validation Evidence">
        {validation ? (
          <>
            <ValidationChecks validation={validation} />
            <p className="ca-detail__note">{validation.note}</p>
          </>
        ) : (
          <>
            <p className="ca-empty">Not validated. Accept is unavailable until the candidate is validated.</p>
            {remediation.patched_code && !decided && (
              <button type="button" className="ca-form__button ca-remediation__button"
                      onClick={handleValidate} disabled={validating}>
                {validating ? 'Running static checks…' : 'Run Patch Validation'}
              </button>
            )}
            {validationError && <p className="ca-error">{validationError}</p>}
          </>
        )}
      </Section>

      <Section letter="F" title="Analyst Decision">
        {notice && <p className="ca-review__warning" role="status">{notice}</p>}
        <PatchActions
          remediationId={remediation.remediation_id}
          policy={policy}
          validationStatus={validation?.status}
          review={review}
          onDecided={handleDecided}
        />
        {!review && (
          <p className="ca-detail__note">
            The review start time could not be recorded; review duration will not be available.
          </p>
        )}
        <p className="ca-detail__note">
          <Link to={`/code-audit/report?scan=${encodeURIComponent(finding.scan_id)}`}>
            View preliminary risk score for this scan →
          </Link>
        </p>
      </Section>
    </ReviewPage>
  )
}
