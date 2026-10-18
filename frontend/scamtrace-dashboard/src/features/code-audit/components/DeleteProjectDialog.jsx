import { useEffect, useRef, useState } from 'react'
import { Trash2 } from 'lucide-react'
import { deleteProject } from '../api/codeAuditApi.js'

/** Confirms and deletes a saved project (all of the user's scans of that repository). */
export default function DeleteProjectDialog({ project, onDeleted, onCancel }) {
  const cancelRef = useRef(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const scanCount = project.scans.length

  useEffect(() => {
    cancelRef.current?.focus()
    function handleKeyDown(event) {
      if (event.key === 'Escape' && !busy) onCancel()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [busy, onCancel])

  async function handleDelete() {
    setBusy(true)
    setError('')
    try {
      await deleteProject(project.latest_scan_id)
      onDeleted(project)
    } catch (err) {
      setError(err.message)
      setBusy(false)
    }
  }

  return (
    <div className="ca-dialog" role="presentation">
      <div className="ca-dialog__box" role="alertdialog" aria-modal="true"
           aria-labelledby="ca-delete-title" aria-describedby="ca-delete-message">
        <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-st-error-bg text-st-error">
          <Trash2 className="h-5 w-5" aria-hidden="true" />
        </div>
        <h4 id="ca-delete-title">Delete project “{project.name}”?</h4>
        <p id="ca-delete-message" className="text-sm leading-relaxed text-st-muted">
          This removes {scanCount === 1 ? 'its saved scan' : `all ${scanCount} saved scans`} of{' '}
          <span className="font-semibold text-st-ink">{project.repository_url.replace('https://', '')}</span>{' '}
          from your projects, history and dashboard, along with the stored copy of its code. This cannot be undone.
          The GitHub repository itself is not affected.
        </p>
        {error && <p className="ca-error mt-3" role="alert">{error}</p>}
        <div className="ca-review__buttons justify-end !mb-0">
          <button ref={cancelRef} type="button" className="ca-form__button ca-dialog__cancel"
                  onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button type="button" className="ca-form__button ca-review__reject" onClick={handleDelete} disabled={busy}>
            {busy ? 'Deleting…' : 'Delete project'}
          </button>
        </div>
      </div>
    </div>
  )
}
