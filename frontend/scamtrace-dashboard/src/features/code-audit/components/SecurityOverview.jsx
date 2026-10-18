import { useCallback, useState } from 'react'
import FindingDrawer from './FindingDrawer.jsx'
import FindingTable from './FindingTable.jsx'
import SeverityCard from './SeverityCard.jsx'

const SEVERITIES = [
  ['Critical', 'CRITICAL', 'critical'],
  ['High', 'HIGH', 'high'],
  ['Medium', 'MEDIUM', 'medium'],
  ['Low', 'LOW', 'low'],
]

/** Severity cards and findings table; a row opens its details in a side panel. */
export default function SecurityOverview({ audit, summary }) {
  const {
    findings, findingsLoading, findingsError,
    severityFilter, filterBySeverity,
    selectedFinding, detailLoading, selectFinding, clearSelectedFinding,
  } = audit
  const [activeId, setActiveId] = useState(null)

  const rows = findings?.findings || []
  const activeIndex = rows.findIndex((row) => row.finding_id === activeId)

  const open = useCallback((findingId) => {
    setActiveId(findingId)
    selectFinding(findingId)
  }, [selectFinding])

  const close = useCallback(() => {
    setActiveId(null)
    clearSelectedFinding()
  }, [clearSelectedFinding])

  return (
    <section className="ca-summary ca-security">
      <h2 className="ca-summary__title">Static Security Overview</h2>

      {summary && (
        <div className="ca-sev-cards">
          <SeverityCard
            label="All" count={summary.total} severity={null}
            active={severityFilter === null} onSelect={filterBySeverity}
          />
          {SEVERITIES.map(([label, severity, key]) => (
            <SeverityCard
              key={severity} label={label} count={summary[key]} severity={severity}
              active={severityFilter === severity} onSelect={filterBySeverity}
            />
          ))}
        </div>
      )}

      {findingsLoading && <p className="ca-loading">Loading findings…</p>}
      {findingsError && <p className="ca-error ca-error--server">{findingsError}</p>}

      {!findingsLoading && !findingsError && findings && (
        rows.length > 0 ? (
          <>
            <p className="ca-form__hint mb-3">Select a finding to see its details, code and AI remediation.</p>
            <FindingTable findings={rows} onSelect={open} selectedId={activeId} />
          </>
        ) : (
          <p className="ca-empty">
            {severityFilter
              ? `No ${severityFilter.toLowerCase()} severity findings for this scan.`
              : 'No static security findings were detected by the configured rules.'}
          </p>
        )
      )}

      {activeIndex >= 0 && (
        <FindingDrawer
          item={rows[activeIndex]}
          finding={selectedFinding}
          loading={detailLoading}
          position={activeIndex + 1}
          total={rows.length}
          onPrevious={() => activeIndex > 0 && open(rows[activeIndex - 1].finding_id)}
          onNext={() => activeIndex < rows.length - 1 && open(rows[activeIndex + 1].finding_id)}
          onClose={close}
        />
      )}
    </section>
  )
}
