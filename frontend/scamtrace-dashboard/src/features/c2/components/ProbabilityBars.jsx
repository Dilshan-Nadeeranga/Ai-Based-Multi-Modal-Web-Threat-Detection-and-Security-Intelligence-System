import { ARM_LABELS, CLASS_LABELS } from '../constants.js'

function Bar({ label, value, max = 1, tone = 'bg-[color:var(--c2-accent-solid)]', strong = false, suffix }) {
  const width = Math.max(0, Math.min(100, (value / max) * 100))
  return (
    <li className="grid grid-cols-[minmax(9.5rem,13rem)_1fr_3.5rem] items-center gap-3 text-sm">
      <span className={`truncate ${strong ? 'font-semibold text-[color:var(--c2-fg-strong)]' : 'text-[color:var(--c2-fg-2)]'}`}>{label}</span>
      <span className="h-2.5 overflow-hidden rounded-full bg-[color:var(--c2-track)]" aria-hidden="true">
        <span className={`block h-full rounded-full ${tone}`} style={{ width: `${width}%` }} />
      </span>
      <span className="text-right font-mono text-xs text-[color:var(--c2-fg)]">{suffix ?? `${(value * 100).toFixed(1)}%`}</span>
    </li>
  )
}

/** Fused class probabilities, highest first. */
export function ProbabilityBars({ probabilities, highlight }) {
  const entries = Object.entries(probabilities || {}).sort((a, b) => b[1] - a[1])
  if (!entries.length) return <p className="text-sm text-[color:var(--c2-fg-muted)]">No probabilities (no page was analyzed).</p>
  return (
    <ul className="flex flex-col gap-2" aria-label="Fused class probabilities">
      {entries.map(([name, value]) => (
        <Bar
          key={name}
          label={CLASS_LABELS[name] || name}
          value={value}
          strong={name === highlight}
          tone={name === 'benign' ? 'bg-[color:var(--c2-ok-solid)]' : name === highlight ? 'bg-[color:var(--c2-mal-solid)]' : 'bg-[color:var(--c2-accent-70)]'}
        />
      ))}
    </ul>
  )
}

/** Each arm's share of the explained class (renormalized weight × arm probability). */
export function ArmContributions({ explanation, modalities }) {
  const contributions = Object.entries(explanation?.arm_contributions || {}).sort((a, b) => b[1] - a[1])
  if (!contributions.length) return <p className="text-sm text-[color:var(--c2-fg-muted)]">No fusion explanation for this result.</p>
  const weights = {}
  Object.values(modalities || {}).forEach((modality) =>
    (modality?.arms || []).forEach((arm) => {
      weights[arm.arm] = arm.fusion_weight
    }),
  )
  const max = Math.max(...contributions.map(([, value]) => value), 0.0001)
  return (
    <div className="flex flex-col gap-2">
      <p className="text-xs text-[color:var(--c2-fg-muted)]">
        Contribution to <span className="font-mono text-[color:var(--c2-fg)]">{CLASS_LABELS[explanation.explained_class] || explanation.explained_class}</span>
        {explanation.driving_arm && (
          <>
            {' '}· driving arm <span className="font-mono text-[color:var(--c2-accent-hi)]">{ARM_LABELS[explanation.driving_arm] || explanation.driving_arm}</span>
          </>
        )}
      </p>
      <ul className="flex flex-col gap-2" aria-label="Per-arm contribution">
        {contributions.map(([arm, value]) => (
          <Bar
            key={arm}
            label={`${ARM_LABELS[arm] || arm}${weights[arm] !== undefined && weights[arm] !== null ? ` (w ${weights[arm].toFixed(2)})` : ''}`}
            value={value}
            max={max}
            strong={arm === explanation.driving_arm}
            tone="bg-[color:var(--c2-accent-solid)]"
            suffix={value.toFixed(3)}
          />
        ))}
      </ul>
    </div>
  )
}
