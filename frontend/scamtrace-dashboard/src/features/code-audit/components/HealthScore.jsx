const LABELS = {
  GOOD: 'Good',
  FAIR: 'Fair',
  NEEDS_ATTENTION: 'Needs attention',
  POOR: 'Poor',
}

/** Code-health score (100 − quality penalty); unavailable when AST analysis did not complete. */
export default function HealthScore({ score, label }) {
  if (score === null || score === undefined) {
    return <span className="ca-risk__muted">Unavailable (AST analysis incomplete)</span>
  }
  return (
    <span>
      {score.toFixed(0)}/100{' '}
      <span className={`ca-risk__health ca-risk__health--${label.toLowerCase()}`}>
        {LABELS[label] || label}
      </span>
    </span>
  )
}
