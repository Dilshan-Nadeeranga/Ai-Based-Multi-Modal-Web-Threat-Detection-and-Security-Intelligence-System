/**
 * Read-only unified diff (as stored by Patch Validation). Lines are rendered
 * as plain text; the diff is never re-generated or applied here.
 */
export default function DiffViewer({ diff }) {
  if (!diff) return <p className="ca-detail__note">No differences.</p>
  return (
    <pre className="ca-detail__code ca-diff" aria-label="Unified diff: original versus suggested">
      {diff.split('\n').map((line, index) => {
        let kind = ''
        if (line.startsWith('+++') || line.startsWith('---')) kind = 'ca-diff__file'
        else if (line.startsWith('@@')) kind = 'ca-diff__hunk'
        else if (line.startsWith('+')) kind = 'ca-diff__add'
        else if (line.startsWith('-')) kind = 'ca-diff__del'
        return (
          <span key={index} className={`ca-diff__line ${kind}`}>
            {line || ' '}
          </span>
        )
      })}
    </pre>
  )
}
