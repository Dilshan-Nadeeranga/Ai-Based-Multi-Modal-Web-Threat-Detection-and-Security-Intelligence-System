import { useState } from 'react'
import { applyAcceptedPatch, submitReviewDecision } from '../api/codeAuditApi.js'

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

function PatchApplication({ review, remediationId, onDecided }) {
  const [applying, setApplying] = useState(false)
  const [error, setError] = useState(null)

  if (review.decision !== 'ACCEPTED') {
    return <dd>Not applied — the patch was rejected</dd>
  }
  if (review.patch_applied) {
    return (
      <dd>
        <span className="ca-badge ca-badge--completed">PATCH APPLIED</span>{' '}
        to the stored copy: <span className="ca-detail__file">{review.patch_target_file}</span>
        {review.patch_start_line && ` · lines ${review.patch_start_line}–${review.patch_end_line}`}
        {review.patch_applied_at && ` · ${formatDate(review.patch_applied_at)}`}
        <br />
        <span className="ca-detail__note">The GitHub repository itself was not changed.</span>
      </dd>
    )
  }

  async function retry() {
    setApplying(true)
    setError(null)
    try {
      onDecided(await applyAcceptedPatch(remediationId))
    } catch (err) {
      setError(err.message)
    } finally {
      setApplying(false)
    }
  }

  return (
    <dd>
      <span className="ca-badge ca-badge--failed">NOT APPLIED</span>{' '}
      {review.patch_application_message || 'The patch has not been applied to the stored copy yet.'}
      <br />
      <button type="button" className="ca-form__button ca-review__accept mt-2" onClick={retry} disabled={applying}>
        {applying ? 'Applying patch…' : 'Apply patch again'}
      </button>
      {error && <p className="ca-error" role="alert">{error}</p>}
    </dd>
  )
}

/** Summary of a recorded analyst decision and the patch application result. */
export function ReviewOutcome({ review, remediationId, onDecided }) {
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
        <PatchApplication review={review} remediationId={remediationId} onDecided={onDecided} />
      </div>
      <div>
        <dt>Review ID</dt>
        <dd className="ca-detail__file">{review.review_id}</dd>
      </div>
    </dl>
  )
}

/**
 * Human Accept / Reject decision with confirmation. Accepting also applies the patch to
 * the project's stored repository copy; it never calls an LLM and never commits or pushes.
 */
export default function PatchActions({ remediationId, policy, validationStatus, review, onDecided }) {
  const [pending, setPending] = useState(null) // 'ACCEPTED' | 'REJECTED' while confirming
  const [quickReason, setQuickReason] = useState('')
  const [reason, setReason] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState(null)

  if (review && review.decision !== 'PENDING') {
    return <ReviewOutcome review={review} remediationId={remediationId} onDecided={onDecided} />
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
        Accepting records your decision and applies the patch to the project&apos;s stored copy of the
        repository. It does not modify the GitHub repository.
      </p>
      {error && <p className="ca-error" role="alert">{error}</p>}

      {pending && (
        <div className="ca-dialog" role="dialog" aria-modal="true" aria-labelledby="ca-dialog-title">
          <div className="ca-dialog__box">
            <h4 id="ca-dialog-title">
              {pending === 'ACCEPTED' ? 'Accept this remediation suggestion?' : 'Reject remediation?'}
            </h4>
            {pending === 'ACCEPTED' ? (
              <p>
                This will record your analyst decision and apply the patch to the code in the
                project&apos;s stored copy of the repository.
                <br />
                It will NOT change the GitHub repository.
              </p>
            ) : (
              <p>
                This will record your analyst decision.
                <br />
                No code will be changed.
              </p>
            )}
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
                {submitting
                  ? pending === 'ACCEPTED' ? 'Applying patch…' : 'Saving decision…'
                  : pending === 'ACCEPTED' ? 'Accept & Apply Patch' : 'Confirm Reject'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
