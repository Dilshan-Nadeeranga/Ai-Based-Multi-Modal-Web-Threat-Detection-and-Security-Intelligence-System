import { defangText } from '../api/defang.js'

const KIND_STYLE = {
  source: { label: 'SOURCE', tone: 'text-[color:var(--c2-sus)] ring-[color:var(--c2-sus-ring)]' },
  sink: { label: 'SINK', tone: 'text-[color:var(--c2-mal)] ring-[color:var(--c2-mal-ring)]' },
  flow_step: { label: 'FLOW', tone: 'text-[color:var(--c2-accent)] ring-[color:var(--c2-accent-ring)]' },
  detection: { label: 'CODE', tone: 'text-[color:var(--c2-fg-2)] ring-[color:var(--c2-neutral-ring)]' },
  html: { label: 'HTML', tone: 'text-[color:var(--c2-fg-2)] ring-[color:var(--c2-neutral-ring)]' },
  script: { label: 'SCRIPT', tone: 'text-[color:var(--c2-fg-2)] ring-[color:var(--c2-neutral-ring)]' },
}

/** Part 8 evidence chain (source → … → sink) as numbered steps. Code is shown as text only. */
export default function EvidenceChain({ steps }) {
  if (!steps?.length) return null
  return (
    <ol className="mt-2 flex flex-col gap-1.5" aria-label="Evidence chain">
      {steps.map((step, index) => {
        const style = KIND_STYLE[step.kind] || KIND_STYLE.detection
        return (
          <li key={`${index}-${step.line}`} className="grid grid-cols-[1.75rem_4.5rem_1fr] items-start gap-2">
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-[color:var(--c2-track)] font-mono text-xs text-[color:var(--c2-fg)]">
              {index + 1}
            </span>
            <span className={`mt-0.5 inline-flex justify-center rounded px-1 py-0.5 font-mono text-[0.625rem] ring-1 ${style.tone}`}>
              {style.label}
              {step.line ? ` L${step.line}` : ''}
            </span>
            <span className="min-w-0">
              <code className="block overflow-x-auto whitespace-pre rounded bg-[color:var(--c2-code-bg)] px-2 py-1 font-mono text-xs text-[color:var(--c2-fg-hi)]">
                {defangText(step.code)}
              </code>
              {step.note && <span className="mt-0.5 block text-xs text-[color:var(--c2-fg-muted)]">{defangText(step.note)}</span>}
            </span>
          </li>
        )
      })}
    </ol>
  )
}
