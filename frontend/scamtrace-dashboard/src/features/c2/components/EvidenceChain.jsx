import { defangText } from '../api/defang.js'

const KIND_STYLE = {
  source: { label: 'SOURCE', tone: 'text-amber-300 ring-amber-400/40' },
  sink: { label: 'SINK', tone: 'text-red-300 ring-red-400/50' },
  flow_step: { label: 'FLOW', tone: 'text-cyan-300 ring-cyan-400/40' },
  detection: { label: 'CODE', tone: 'text-slate-300 ring-slate-500/50' },
  html: { label: 'HTML', tone: 'text-slate-300 ring-slate-500/50' },
  script: { label: 'SCRIPT', tone: 'text-slate-300 ring-slate-500/50' },
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
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-slate-800 font-mono text-xs text-slate-200">
              {index + 1}
            </span>
            <span className={`mt-0.5 inline-flex justify-center rounded px-1 py-0.5 font-mono text-[0.625rem] ring-1 ${style.tone}`}>
              {style.label}
              {step.line ? ` L${step.line}` : ''}
            </span>
            <span className="min-w-0">
              <code className="block overflow-x-auto whitespace-pre rounded bg-black/50 px-2 py-1 font-mono text-xs text-slate-100">
                {defangText(step.code)}
              </code>
              {step.note && <span className="mt-0.5 block text-xs text-slate-400">{defangText(step.note)}</span>}
            </span>
          </li>
        )
      })}
    </ol>
  )
}
