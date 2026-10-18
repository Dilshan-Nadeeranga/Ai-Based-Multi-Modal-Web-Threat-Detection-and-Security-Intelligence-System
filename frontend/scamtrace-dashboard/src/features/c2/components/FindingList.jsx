import { useState } from 'react'
import { ArrowUpCircle, ChevronDown } from 'lucide-react'
import { defangText } from '../api/defang.js'
import { MODALITY, SEVERITY_RANK, SEVERITY_STYLE } from '../constants.js'
import EvidenceChain from './EvidenceChain.jsx'

function Finding({ finding }) {
  const [open, setOpen] = useState(false)
  const modality = MODALITY[finding.modality] || MODALITY.fusion
  const Icon = modality.icon
  const hasChain = finding.steps?.length > 0
  return (
    <li className="c2-enter rounded-lg border border-slate-800 bg-slate-900/60 p-3">
      <div className="flex items-start gap-3">
        <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-slate-800 text-cyan-300" title={modality.label}>
          <Icon className="h-4 w-4" aria-hidden="true" />
          <span className="sr-only">{modality.label}</span>
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className={`rounded px-1.5 py-0.5 font-mono text-[0.6875rem] font-semibold uppercase ring-1 ${SEVERITY_STYLE[finding.severity] || SEVERITY_STYLE.info}`}>
              {finding.severity}
            </span>
            <span className="font-mono text-[0.6875rem] uppercase tracking-wider text-slate-400">{modality.label}</span>
            {finding.raises_verdict && (
              <span className="inline-flex items-center gap-1 rounded bg-red-500/10 px-1.5 py-0.5 font-mono text-[0.6875rem] text-red-200 ring-1 ring-red-400/40">
                <ArrowUpCircle className="h-3 w-3" aria-hidden="true" /> raised the verdict
              </span>
            )}
          </div>
          <p className="mt-1 font-semibold text-slate-50">{defangText(finding.title)}</p>
          <p className="mt-0.5 text-sm text-slate-300">{defangText(finding.detail)}</p>
          {finding.evidence && (
            <code className="mt-2 block overflow-x-auto whitespace-pre rounded bg-black/50 px-2 py-1 font-mono text-xs text-amber-100">
              {defangText(finding.evidence)}
            </code>
          )}
          {hasChain && (
            <>
              <button
                type="button"
                onClick={() => setOpen((value) => !value)}
                aria-expanded={open}
                className="mt-2 inline-flex items-center gap-1 text-xs font-medium text-cyan-300 hover:text-cyan-100"
              >
                <ChevronDown className={`h-3.5 w-3.5 transition ${open ? 'rotate-180' : ''}`} aria-hidden="true" />
                {open ? 'Hide' : 'Show'} evidence chain ({finding.steps.length} steps)
              </button>
              {open && <EvidenceChain steps={finding.steps} />}
            </>
          )}
        </div>
      </div>
    </li>
  )
}

/** "Why?" — findings sorted by severity (stable: C2's own ranking breaks ties). */
export default function FindingList({ findings, total, omitted }) {
  const sorted = [...(findings || [])]
    .map((finding, index) => ({ finding, index }))
    .sort((a, b) => (SEVERITY_RANK[b.finding.severity] ?? 0) - (SEVERITY_RANK[a.finding.severity] ?? 0) || a.index - b.index)
    .map(({ finding }) => finding)
  if (!sorted.length) return <p className="text-sm text-slate-400">No findings — nothing on this page raised a concern.</p>
  return (
    <div>
      <ul className="flex flex-col gap-2">
        {sorted.map((finding, index) => (
          <Finding key={`${finding.id}-${index}`} finding={finding} />
        ))}
      </ul>
      {omitted > 0 && (
        <p className="mt-2 text-xs text-slate-400">
          Showing {sorted.length} of {total} findings ({omitted} lower-ranked omitted by C2).
        </p>
      )}
    </div>
  )
}
