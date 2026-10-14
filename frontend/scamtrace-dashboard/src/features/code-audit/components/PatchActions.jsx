import { useState } from 'react'
import { submitReviewDecision } from '../api/codeAuditApi.js'

const QUICK_REASONS = [
  'Security issue remains',
  'Incorrect behavior',
  'Invalid repository assumption',
  'Excessive code change',
  'Introduces new issue',
  'Other',
]

const SAVE_FAILED = 'Decision could not be saved. No repository changes were made. Try again.'

function formatDate(value) {
  return value ? new Date(value).toLocaleString() : '—'
}

function formatDuration(seconds) {
  if (seconds === null || seconds === undefined) return 'Not available (review start time unknown)'
  if (seconds < 60) return `${seconds} second${seconds === 1 ? '' : 's'}`
  const minutes = Math.floor(seconds / 60)
  return `${minutes} min ${seconds % 60} s`
}

/** Read-only summary of a recorded analyst decision. */
export function ReviewOutcome({ review }) {
  return (
    <dl className="ca-detail__grid ca-review__outcome">
      <div>
        <dt>Analyst Decision</dt>
        <dd>
          <span className={`ca-badge ${review.decision === 'ACCEPTED' ? 'ca-badge--completed' : 'ca-badge--failed'}`}>
            {review.decision}
          </span>
        </dd>
      </div>
      {review.decision === 'REJECTED' && (
        <div>
          <dt>Reason</dt>
          <dd>{review.rejection_reason || 'No reason given'}</dd>
        </div>
      )}
      <div>
        <dt>Reviewed</dt>
        <dd>{formatDate(review.reviewed_at)}</dd>
      </div>
      <div>
        <dt>Review Duration</dt>
        <dd>{formatDuration(review.review_duration_seconds)}</dd>
      </div>
      <div>
        <dt>Validation at Decision</dt>
        <dd>{review.validation_status}</dd>
      </div>
      <div>
        <dt>Patch Application</dt>
        <dd>NOT APPLIED — no code changes applied to the repository</dd>
      </div>
      <div>
        <dt>Review ID</dt>
        <dd className="ca-detail__file">{review.review_id}</dd>
      </div>
    </dl>
  )
}

/**
 * Human Accept / Reject decision with confirmation. Only records the decision;
 * it never calls an LLM and never applies, commits or deploys the patch.
 */
export default function PatchActions({ remediationId, policy, validationStatus, review, onDecided }) {
  const [pending, setPending] = useState(null) // 'ACCEPTED' | 'REJECTED' while confirming
  const [quickReason, setQuickReason] = useState('')
  const [reason, setReason] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  if (review && review.decision !== 'PENDING') {
    return <ReviewOutcome review={review} />
  }

  function open(decision) {
    setError(null)
    setPending(decision)
  }

  function cancel() {
    if (submitting) return
    setPending(null)
    setQuickReason('')
    setReason('')
  }

  async function confirm() {
    if (submitting) return
    setSubmitting(true)
    setError(null)
    const fullReason =
      pending === 'REJECTED'
        ? [quickReason, reason.trim()].filter(Boolean).join(': ') || null
        : null
    try {
      const saved = await submitReviewDecision(remediationId, pending, fullReason)
      setPending(null)
      onDecided(saved)
    } catch (err) {
      if (err.code === 'REVIEW_ALREADY_DECIDED' && err.data?.review) {
        setPending(null)
        onDecided(err.data.review, 'A decision had already been recorded for this remediation. It was not changed.')
      } else if (err.code === 'ACCEPT_NOT_ALLOWED') {
        setError(err.message)
      } else {
        setError(err.status === 0 ? `Backend is unavailable. ${SAVE_FAILED}` : SAVE_FAILED)
      }
    } finally {
      setSubmitting(false)
    }
  }

  const statusText = {
    PASSED: 'The generated remediation passed the configured static validation checks. Human approval is still required.',
    PASSED_WITH_WARNINGS: 'The candidate passed validation with warnings. Review the warnings above before deciding.',
  }[validationStatus]

  return (
    <div className="ca-review__decision">
      <p className="ca-remediation__status">
        <span className="ca-badge ca-badge--unvalidated">Awaiting Analyst Review</span>
        <span>Validation status: <strong>{validationStatus || 'NOT_VALIDATED'}</strong></span>
      </p>
      {statusText && <p>{statusText}</p>}
      {policy.has_warnings && policy.accept_allowed && (
        <p className="ca-review__warning" role="alert">
          ⚠ Deterministic validation reported warnings for this candidate. Accept only if you have
          reviewed them.
        </p>
      )}
      {!policy.accept_allowed && policy.accept_blocked_reason && (
        <p className="ca-review__blocked" role="note">{policy.accept_blocked_reason}</p>
      )}

      <div className="ca-review__buttons">
        <button
          type="button"
          className="ca-form__button ca-review__accept"
          disabled={!policy.accept_allowed || submitting || pending !== null}
          onClick={() => open('ACCEPTED')}
        >
          Accept Patch
        </button>
        <button
          type="button"
          className="ca-form__button ca-review__reject"
          disabled={!policy.reject_allowed || submitting || pending !== null}
          onClick={() => open('REJECTED')}
        >
          Reject Patch
        </button>
      </div>
      <p className="ca-detail__note">
        Accepting records your decision only. It does not modify the GitHub repository.
      </p>
      {error && <p className="ca-error" role="alert">{error}</p>}

      {pending && (
        <div className="ca-dialog" role="dialog" aria-modal="true" aria-labelledby="ca-dialog-title">
          <div className="ca-dialog__box">
            <h4 id="ca-dialog-title">
              {pending === 'ACCEPTED' ? 'Accept this remediation suggestion?' : 'Reject remediation?'}
            </h4>
            <p>
              This will record your analyst decision.
              <br />
              It will NOT modify the repository.
            </p>
            {pending === 'REJECTED' && (
              <>
                <label className="ca-form__label" htmlFor="ca-reject-quick">Reason (optional)</label>
                <select
                  id="ca-reject-quick"
                  className="ca-form__input"
                  value={quickReason}
                  onChange={(event) => setQuickReason(event.target.value)}
                  disabled={submitting}
                >
                  <option value="">— Select a reason —</option>
                  {QUICK_REASONS.map((item) => (
                    <option key={item} value={item}>{item}</option>
                  ))}
                </select>
                <textarea
                  className="ca-form__input ca-dialog__reason"
                  placeholder="Additional details (optional)"
                  maxLength={900}
                  rows={3}
                  value={reason}
                  onChange={(event) => setReason(event.target.value)}
                  disabled={submitting}
                />
              </>
            )}
            {error && <p className="ca-error" role="alert">{error}</p>}
            <div className="ca-review__buttons">
              <button type="button" className="ca-form__button ca-dialog__cancel" onClick={cancel} disabled={submitting}>
                Cancel
              </button>
              <button
                type="button"
                className={`ca-form__button ${pending === 'ACCEPTED' ? 'ca-review__accept' : 'ca-review__reject'}`}
                onClick={confirm}
                disabled={submitting}
              >
                {submitting ? 'Saving decision…' : pending === 'ACCEPTED' ? 'Confirm Accept' : 'Confirm Reject'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
