import { useEffect, useRef } from 'react'
import { ChevronLeft, ChevronRight, X } from 'lucide-react'
import FindingDetails from './FindingDetails.jsx'
import SeverityBadge from './SeverityBadge.jsx'

/**
 * Right-hand slide-over showing one finding without leaving the table.
 * `item` is the table row (shown immediately); `finding` is the loaded detail.
 */
export default function FindingDrawer({ item, finding, loading, position, total, onPrevious, onNext, onClose }) {
  const panelRef = useRef(null)
  const bodyRef = useRef(null)

  useEffect(() => {
    const returnFocus = document.activeElement
    const root = document.documentElement
    const { body } = document
    const saved = { rootOverflow: root.style.overflow, bodyOverflow: body.style.overflow, padding: body.style.paddingRight }
    const scrollbarWidth = window.innerWidth - root.clientWidth
    root.style.overflow = 'hidden'
    body.style.overflow = 'hidden'
    if (scrollbarWidth > 0) body.style.paddingRight = `${scrollbarWidth}px`
    panelRef.current?.focus({ preventScroll: true })
    return () => {
      root.style.overflow = saved.rootOverflow
      body.style.overflow = saved.bodyOverflow
      body.style.paddingRight = saved.padding
      returnFocus?.focus?.({ preventScroll: true })
    }
  }, [])

  useEffect(() => {
    bodyRef.current?.scrollTo({ top: 0 })
  }, [item.finding_id])

  useEffect(() => {
    function handleKeyDown(event) {
      if (event.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  const ready = finding && finding.finding_id === item.finding_id && !loading

  return (
    <div className="ca-drawer">
      <button type="button" className="ca-drawer__backdrop" aria-label="Close finding details" onClick={onClose} />
      <aside
        ref={panelRef}
        className="ca-drawer__panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="ca-drawer-title"
        tabIndex={-1}
      >
        <header className="ca-drawer__header">
          <div className="ca-drawer__toolbar">
            <div className="ca-drawer__nav">
              <button type="button" className="ca-drawer__icon-btn" onClick={onPrevious}
                      disabled={position <= 1} aria-label="Previous finding">
                <ChevronLeft className="h-4 w-4" aria-hidden="true" />
              </button>
              <span className="ca-drawer__position">{position} of {total}</span>
              <button type="button" className="ca-drawer__icon-btn" onClick={onNext}
                      disabled={position >= total} aria-label="Next finding">
                <ChevronRight className="h-4 w-4" aria-hidden="true" />
              </button>
            </div>
            <button type="button" className="ca-drawer__icon-btn" onClick={onClose} aria-label="Close finding details">
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
          <SeverityBadge severity={item.severity} />
          <h3 id="ca-drawer-title" className="ca-drawer__title">{item.title}</h3>
          <p className="ca-drawer__location">
            {item.file_path}:{item.start_line}
          </p>
        </header>

        <div ref={bodyRef} className="ca-drawer__body">
          {ready && <FindingDetails finding={finding} />}
          {!ready && loading && <p className="ca-loading !mt-0">Loading finding details…</p>}
          {!ready && !loading && (
            <p className="ca-error" role="alert">Unable to load finding details. Please try again.</p>
          )}
        </div>
      </aside>
    </div>
  )
}
