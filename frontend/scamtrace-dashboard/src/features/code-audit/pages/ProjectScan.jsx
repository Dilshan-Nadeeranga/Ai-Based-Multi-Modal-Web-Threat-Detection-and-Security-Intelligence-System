import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { CalendarClock, RefreshCw, Trash2 } from 'lucide-react'
import AppShell from '../../../components/AppShell.jsx'
import { CODE_AUDIT_SECTION } from '../navigation.js'
import DeleteProjectDialog from '../components/DeleteProjectDialog.jsx'
import RiskScorePanel from '../components/RiskScorePanel.jsx'
import ScanSummary from '../components/ScanSummary.jsx'
import SecurityOverview from '../components/SecurityOverview.jsx'
import { useCodeAudit } from '../hooks/useCodeAudit.js'
import { formatScanDate, notifyProjectsChanged, useProjects } from '../hooks/useProjects.js'
import '../codeAudit.css'

/** Route entry: remount per scan so no finding state leaks between scans. */
export default function ProjectScan() {
  const { scanId } = useParams()
  return <ProjectScanView key={scanId} scanId={scanId} />
}

function ScanHistory({ project, scanId, onRescan, onDelete, rescanning }) {
  const navigate = useNavigate()
  return (
    <section className="ca-card flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
      <div className="flex min-w-0 flex-1 flex-col gap-2">
        <label className="ca-form__label flex items-center gap-1.5" htmlFor="ca-scan-history">
          <CalendarClock className="h-4 w-4" aria-hidden="true" /> Scan history
        </label>
        <select
          id="ca-scan-history"
          className="ca-form__input md:max-w-md"
          value={scanId}
          disabled={!project || rescanning}
          onChange={(event) => navigate(`/code-audit/scans/${encodeURIComponent(event.target.value)}`)}
        >
          {project
            ? project.scans.map((scan, index) => (
                <option key={scan.scan_id} value={scan.scan_id}>
                  {formatScanDate(scan.created_at)}{index === 0 ? ' (latest)' : ''} · {scan.status}
                </option>
              ))
            : <option value={scanId}>{scanId}</option>}
        </select>
        <p className="ca-form__hint">
          {project
            ? `${project.scans.length} ${project.scans.length === 1 ? 'scan' : 'scans'} saved for this repository. Pick any date to view that result.`
            : 'Loading scan history…'}
        </p>
      </div>
      <div className="flex flex-col gap-2 sm:flex-row md:mb-6">
        <button
          type="button"
          className="ca-form__button inline-flex items-center justify-center gap-2"
          onClick={onRescan}
          disabled={!project || rescanning}
        >
          <RefreshCw className={`h-4 w-4 ${rescanning ? 'animate-spin' : ''}`} aria-hidden="true" />
          {rescanning ? 'Re-scanning…' : 'Re-scan repository'}
        </button>
        <button
          type="button"
          className="inline-flex items-center justify-center gap-2 rounded-lg border border-st-error/40 bg-white px-4 py-2.5 text-[15px] font-semibold text-st-error transition hover:bg-st-error-bg disabled:cursor-not-allowed disabled:opacity-50"
          onClick={onDelete}
          disabled={!project || rescanning}
        >
          <Trash2 className="h-4 w-4" aria-hidden="true" /> Delete project
        </button>
      </div>
    </section>
  )
}

function ProjectScanView({ scanId }) {
  const navigate = useNavigate()
  const audit = useCodeAudit()
  const { openScan, result, scanLoading, scanError, analyze, loading: rescanning, error: rescanError, findings } = audit
  const { projects } = useProjects()
  const project = projects?.find((item) => item.scans.some((scan) => scan.scan_id === scanId))
  const [confirmDelete, setConfirmDelete] = useState(false)

  function handleDeleted() {
    notifyProjectsChanged()
    navigate('/code-audit', { replace: true })
  }

  useEffect(() => {
    openScan(scanId)
  }, [openScan, scanId])

  async function handleRescan() {
    const data = await analyze(project.repository_url)
    if (data?.scan_id) {
      notifyProjectsChanged()
      navigate(`/code-audit/scans/${encodeURIComponent(data.scan_id)}`)
    }
  }

  const title = project?.name || result?.repository?.name || 'Project'
  const summary = findings?.summary || result?.finding_summary || null

  return (
    <AppShell title={title} section={CODE_AUDIT_SECTION}>
      <div className="ca-page">
        <header className="ca-page__header">
          <Link to="/code-audit" className="ca-review__back">← All projects</Link>
          <span className="ca-page__badge">Project</span>
          <h1>{title}</h1>
          {(project || result) && (
            <p className="ca-page__subtitle">
              {project?.owner || result?.repository?.owner} ·{' '}
              <a href={project?.repository_url || result?.repository?.url} target="_blank" rel="noreferrer">
                {(project?.repository_url || result?.repository?.url || '').replace('https://', '')}
              </a>
            </p>
          )}
        </header>

        {!scanError && (
          <ScanHistory project={project} scanId={scanId} onRescan={handleRescan}
                       onDelete={() => setConfirmDelete(true)} rescanning={rescanning} />
        )}
        {confirmDelete && project && (
          <DeleteProjectDialog project={project} onDeleted={handleDeleted} onCancel={() => setConfirmDelete(false)} />
        )}
        {rescanning && <p className="ca-loading !mt-0">Static security analysis is running on the latest code…</p>}
        {rescanError && <p className="ca-error">{rescanError}</p>}

        {scanLoading && <p className="ca-loading !mt-0">Loading saved scan…</p>}
        {scanError && (
          <p className="ca-error" role="alert">
            {scanError} <Link to="/code-audit">Back to your projects</Link>
          </p>
        )}

        {result && <ScanSummary result={result} />}
        {result?.scan_id && <RiskScorePanel scanId={result.scan_id} />}
        {result && <SecurityOverview audit={audit} summary={summary} />}
      </div>
    </AppShell>
  )
}
