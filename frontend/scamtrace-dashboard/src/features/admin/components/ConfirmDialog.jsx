import { useEffect, useRef } from 'react'

/** Modal confirmation for important admin changes. */
export default function ConfirmDialog({ title, message, confirmLabel, danger = false, busy, onConfirm, onCancel }) {
  const cancelRef = useRef(null)

  useEffect(() => {
    cancelRef.current?.focus()
    function onKey(event) {
      if (event.key === 'Escape' && !busy) onCancel()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onCancel])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4" role="presentation">
      <div role="dialog" aria-modal="true" aria-labelledby="confirm-title"
           className="w-full max-w-md rounded-xl border border-slate-700 bg-slate-900 p-6 shadow-2xl space-y-4">
        <h2 id="confirm-title" className="text-lg font-semibold text-slate-100">{title}</h2>
        <p className="text-sm text-slate-300">{message}</p>
        <div className="flex justify-end gap-3">
          <button ref={cancelRef} type="button" onClick={onCancel} disabled={busy}
                  className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:bg-slate-800">
            Cancel
          </button>
          <button type="button" onClick={onConfirm} disabled={busy}
                  className={`rounded-lg px-4 py-2 text-sm font-semibold text-white disabled:opacity-60 ${danger
                    ? 'bg-red-600 hover:bg-red-500' : 'bg-sky-600 hover:bg-sky-500'}`}>
            {busy ? 'Saving…' : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}
