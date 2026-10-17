import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ChevronRight, FolderGit2, History, Trash2 } from 'lucide-react'
import { formatScanDate, notifyProjectsChanged } from '../hooks/useProjects.js'
import DeleteProjectDialog from './DeleteProjectDialog.jsx'

/** Grid of the user's saved repositories; each opens its latest scan. */
export default function ProjectList({ projects, loading, error }) {
  const [deleting, setDeleting] = useState(null)
  const [notice, setNotice] = useState('')

  function handleDeleted(project) {
    setDeleting(null)
    setNotice(`Project “${project.name}” was deleted.`)
    notifyProjectsChanged()
  }

  return (
    <section className="ca-summary" id="projects" aria-labelledby="ca-projects-title">
      <div className="mb-5 flex flex-wrap items-baseline justify-between gap-2">
        <h2 id="ca-projects-title" className="ca-summary__title !mb-0">Your Projects</h2>
        {projects?.length > 0 && (
          <span className="text-xs font-semibold text-st-muted">
            {projects.length} {projects.length === 1 ? 'repository' : 'repositories'}
          </span>
        )}
      </div>

      {notice && (
        <p className="mb-4 rounded-lg bg-emerald-50 px-4 py-3 text-sm text-emerald-800" role="status">{notice}</p>
      )}
      {loading && <p className="ca-loading !mt-0">Loading your projects…</p>}
      {error && <p className="ca-error">{error}</p>}

      {projects?.length === 0 && (
        <p className="ca-empty">
          No projects yet. Every repository you analyze is saved here so you can reopen its results any time.
        </p>
      )}

      {projects?.length > 0 && (
        <ul className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {projects.map((project) => (
            <li key={project.repository_url} className="group relative">
              <Link
                to={`/code-audit/scans/${encodeURIComponent(project.latest_scan_id)}`}
                className="flex h-full items-start gap-3 rounded-xl border border-st-container bg-white p-4 pr-12 no-underline transition hover:border-st-navy-2 hover:shadow-[0_1px_8px_rgba(7,28,140,0.08)]"
              >
                <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-st-low text-st-navy-2">
                  <FolderGit2 className="h-5 w-5" aria-hidden="true" />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-manrope text-[0.9375rem] font-bold text-st-navy">{project.name}</span>
                  <span className="block truncate text-xs text-st-muted">{project.owner}</span>
                  <span className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[0.6875rem] text-st-muted">
                    <span className="inline-flex items-center gap-1">
                      <History className="h-3.5 w-3.5" aria-hidden="true" />
                      {project.scans.length} {project.scans.length === 1 ? 'scan' : 'scans'}
                    </span>
                    <span>Last: {formatScanDate(project.last_scanned_at)}</span>
                  </span>
                </span>
                <ChevronRight className="absolute bottom-4 right-4 h-4 w-4 text-st-outline transition group-hover:text-st-navy-2" aria-hidden="true" />
              </Link>
              <button
                type="button"
                onClick={() => { setNotice(''); setDeleting(project) }}
                className="absolute right-2.5 top-2.5 rounded-md p-1.5 text-st-outline transition hover:bg-st-error-bg hover:text-st-error focus-visible:bg-st-error-bg focus-visible:text-st-error"
                aria-label={`Delete project ${project.name}`}
                title="Delete project"
              >
                <Trash2 className="h-4 w-4" aria-hidden="true" />
              </button>
            </li>
          ))}
        </ul>
      )}

      {deleting && (
        <DeleteProjectDialog project={deleting} onDeleted={handleDeleted} onCancel={() => setDeleting(null)} />
      )}
    </section>
  )
}
