/**
 * Read-only, line-numbered source viewer. Code is untrusted text: it is
 * rendered as React text nodes (escaped), never as HTML, and never executed.
 */
export default function CodeViewer({ code, startLine = 1, label }) {
  if (!code) return <p className="ca-detail__note">No code available.</p>
  const first = Number.isInteger(startLine) && startLine > 0 ? startLine : 1
  const lines = code.split('\n')
  const width = String(first + lines.length - 1).length
  return (
    <pre className="ca-detail__code ca-code" aria-label={label}>
      {lines.map((line, index) => (
        <span key={index} className="ca-code__line">
          <span className="ca-code__number" aria-hidden="true">
            {String(first + index).padStart(width, ' ')}
          </span>
          {line || ' '}
        </span>
      ))}
    </pre>
  )
}
