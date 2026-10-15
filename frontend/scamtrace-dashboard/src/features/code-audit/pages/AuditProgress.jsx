import AppShell from '../../../components/AppShell.jsx'
import '../codeAudit.css'

// Placeholder — implemented in a later sprint (asynchronous scan progress).
export default function AuditProgress() {
  return (
    <AppShell title="Audit Progress">
      <div className="ca-page">
        <header className="ca-page__header">
          <span className="ca-page__badge">Component C4</span>
          <h1>Audit Progress</h1>
        </header>
        <p className="ca-empty">Scan progress tracking will be available in a later sprint.</p>
      </div>
    </AppShell>
  )
}
