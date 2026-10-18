import { ChevronRight } from 'lucide-react'
import SeverityBadge from './SeverityBadge.jsx'

/** Table of security findings. Rows open the finding in the side panel. */
export default function FindingTable({ findings, onSelect, selectedId }) {
  if (!findings || findings.length === 0) return null

  function handleKeyDown(event, findingId) {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      onSelect(findingId)
    }
  }

  return (
    <div className="ca-table-wrap">
      <table className="ca-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Finding</th>
            <th>Category</th>
            <th>CWE</th>
            <th>File</th>
            <th>Line</th>
            <th>Status</th>
            <th><span className="sr-only">Details</span></th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding) => (
            <tr
              key={finding.finding_id}
              className={
                finding.finding_id === selectedId ? 'ca-table__row--selected' : ''
              }
              onClick={() => onSelect(finding.finding_id)}
              onKeyDown={(event) => handleKeyDown(event, finding.finding_id)}
              tabIndex={0}
              aria-label={`View details: ${finding.title}`}
            >
              <td><SeverityBadge severity={finding.severity} /></td>
              <td className="ca-table__title">{finding.title}</td>
              <td>{finding.category}</td>
              <td>{(finding.cwe || []).join(', ') || '—'}</td>
              <td className="ca-table__file">{finding.file_path}</td>
              <td>{finding.start_line}</td>
              <td>{finding.status}</td>
              <td className="ca-table__view">
                View <ChevronRight className="h-4 w-4" aria-hidden="true" />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
