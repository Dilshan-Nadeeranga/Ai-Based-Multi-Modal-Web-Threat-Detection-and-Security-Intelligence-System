import AppShell from '../../../components/AppShell.jsx'
import FindingDetails from '../components/FindingDetails.jsx'
import FindingTable from '../components/FindingTable.jsx'
import RepositoryInput from '../components/RepositoryInput.jsx'
import RiskScorePanel from '../components/RiskScorePanel.jsx'
import ScanSummary from '../components/ScanSummary.jsx'
import SeverityCard from '../components/SeverityCard.jsx'
import { useCodeAudit } from '../hooks/useCodeAudit.js'
import '../codeAudit.css'

/**
 * C4 — Code Quality & Vulnerability Auditor.
 * Repository ingestion + static vulnerability analysis (Semgrep).
 */
export default function RepositoryAudit() {
  const {
    loading, error, result, analyze,
    findings, findingsLoading, findingsError,
    severityFilter, filterBySeverity,
    selectedFinding, detailLoading, selectFinding, clearSelectedFinding,
  } = useCodeAudit()

  const summary = findings?.summary || result?.finding_summary || null

  return (
    <AppShell title="Repository Audit">
      <div className="ca-page">
        <header className="ca-page__header">
          <span className="ca-page__badge">Component C4</span>
          <h1>Code Quality &amp; Vulnerability Auditor</h1>
          <p className="ca-page__subtitle">
            Analyze a GitHub repository for code quality and security risks.
          </p>
        </header>

        <section className="ca-card">
          <h2 className="ca-card__title">Repository Analysis</h2>
          <p className="ca-card__description">
            Paste a public GitHub repository URL to begin.
          </p>
          <RepositoryInput onSubmit={analyze} loading={loading} />
          {loading && (
            <p className="ca-loading">Static security analysis is running…</p>
          )}
          {error && <p className="ca-error ca-error--server">{error}</p>}
        </section>

        {result && <ScanSummary result={result} />}

        {result?.scan_id && <RiskScorePanel scanId={result.scan_id} />}

        {result && summary && (
          <section className="ca-summary ca-security">
            <h2 className="ca-summary__title">Static Security Overview</h2>

            <div className="ca-sev-cards">
              <SeverityCard
                label="All" count={summary.total} severity={null}
                active={severityFilter === null} onSelect={filterBySeverity}
              />
              <SeverityCard
                label="Critical" count={summary.critical} severity="CRITICAL"
                active={severityFilter === 'CRITICAL'} onSelect={filterBySeverity}
              />
              <SeverityCard
                label="High" count={summary.high} severity="HIGH"
                active={severityFilter === 'HIGH'} onSelect={filterBySeverity}
              />
              <SeverityCard
                label="Medium" count={summary.medium} severity="MEDIUM"
                active={severityFilter === 'MEDIUM'} onSelect={filterBySeverity}
              />
              <SeverityCard
                label="Low" count={summary.low} severity="LOW"
                active={severityFilter === 'LOW'} onSelect={filterBySeverity}
              />
            </div>

            {findingsLoading && (
              <p className="ca-loading">Loading findings…</p>
            )}
            {findingsError && (
              <p className="ca-error ca-error--server">{findingsError}</p>
            )}

            {!findingsLoading && !findingsError && findings && (
              findings.findings.length > 0 ? (
                <FindingTable
                  findings={findings.findings}
                  onSelect={selectFinding}
                  selectedId={selectedFinding?.finding_id}
                />
              ) : (
                <p className="ca-empty">
                  {severityFilter
                    ? `No ${severityFilter.toLowerCase()} severity findings for this scan.`
                    : 'No static security findings were detected by the configured rules.'}
                </p>
              )
            )}

            <FindingDetails
              finding={selectedFinding}
              loading={detailLoading}
              onClose={clearSelectedFinding}
            />
          </section>
        )}
      </div>
    </AppShell>
  )
}
