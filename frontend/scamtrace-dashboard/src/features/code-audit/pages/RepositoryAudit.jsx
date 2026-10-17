import { useNavigate } from 'react-router-dom'
import AppShell from '../../../components/AppShell.jsx'
import ProjectList from '../components/ProjectList.jsx'
import RepositoryInput from '../components/RepositoryInput.jsx'
import { useCodeAudit } from '../hooks/useCodeAudit.js'
import { notifyProjectsChanged, useProjects } from '../hooks/useProjects.js'
import '../codeAudit.css'

/**
 * C4 — Code Quality & Vulnerability Auditor.
 * Start a new repository analysis or reopen a saved project.
 */
export default function RepositoryAudit() {
  const navigate = useNavigate()
  const { loading, error, analyze } = useCodeAudit()
  const { projects, loading: projectsLoading, error: projectsError } = useProjects()

  async function handleAnalyze(repositoryUrl) {
    const data = await analyze(repositoryUrl)
    if (data?.scan_id) {
      notifyProjectsChanged()
      navigate(`/code-audit/scans/${encodeURIComponent(data.scan_id)}`)
    }
  }

  return (
    <AppShell title="Code Audit">
      <div className="ca-page">
        <header className="ca-page__header">
          <span className="ca-page__badge">Component C4</span>
          <h1>Code Quality &amp; Vulnerability Auditor</h1>
          <p className="ca-page__subtitle">
            Analyze a GitHub repository for code quality and security risks. Every analyzed repository is saved as a
            project, so you can come back to its results any time.
          </p>
        </header>

        <section className="ca-card">
          <h2 className="ca-card__title">New Repository Analysis</h2>
          <p className="ca-card__description">
            Paste a public GitHub repository URL to begin.
          </p>
          <RepositoryInput onSubmit={handleAnalyze} loading={loading} />
          {loading && (
            <p className="ca-loading">Static security analysis is running…</p>
          )}
          {error && <p className="ca-error ca-error--server">{error}</p>}
        </section>

        <ProjectList projects={projects} loading={projectsLoading} error={projectsError} />
      </div>
    </AppShell>
  )
}
