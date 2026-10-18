import { Code2, Languages, LayoutTemplate } from 'lucide-react'
import { defangText } from '../api/defang.js'
import { ARM_LABELS, CLASS_LABELS } from '../constants.js'
import EvidenceChain from './EvidenceChain.jsx'
import { Chip } from './ui.jsx'

const META = {
  dom: { title: 'DOM structure', icon: LayoutTemplate, part: 'Parts 3–4' },
  content: { title: 'Content & language', icon: Languages, part: 'Parts 5–6' },
  behavior: { title: 'JS behavior', icon: Code2, part: 'Parts 7–8' },
}

const STATUS_TONE = { ok: 'green', failed: 'red', skipped: 'slate' }

/** One modality: status, summary, top evidence, its model arm(s); behavior shows its evidence chain. */
export default function ModalityCard({ name, modality, chain }) {
  const meta = META[name]
  const Icon = meta.icon
  if (!modality) return null
  return (
    <article className="c2-panel flex flex-col gap-3 rounded-xl border border-[color:var(--c2-border)] p-4">
      <header className="flex items-start justify-between gap-2">
        <h3 className="flex items-center gap-2 font-semibold text-[color:var(--c2-fg-strong)]">
          <Icon className="h-4 w-4 text-[color:var(--c2-accent)]" aria-hidden="true" />
          {meta.title}
        </h3>
        <Chip tone={STATUS_TONE[modality.status] || 'slate'}>{modality.status}</Chip>
      </header>
      <p className="font-mono text-[0.6875rem] uppercase tracking-wider text-[color:var(--c2-fg-faint)]">{meta.part}</p>
      {modality.reason && <p className="text-sm text-[color:var(--c2-sus-hi)]">{defangText(modality.reason)}</p>}
      {modality.summary && <p className="text-sm text-[color:var(--c2-fg-2)]">{defangText(modality.summary)}</p>}
      {modality.top_evidence?.length > 0 && (
        <ul className="flex flex-col gap-1.5">
          {modality.top_evidence.map((item, index) => (
            <li key={index} className="flex gap-2 text-sm text-[color:var(--c2-fg)]">
              <span className="text-[color:var(--c2-accent-icon)]" aria-hidden="true">›</span>
              <span className="min-w-0 break-words">{defangText(item)}</span>
            </li>
          ))}
        </ul>
      )}
      {chain?.length > 0 && (
        <div>
          <p className="font-mono text-[0.6875rem] uppercase tracking-wider text-[color:var(--c2-fg-muted)]">Source → sink evidence</p>
          <EvidenceChain steps={chain.slice(0, 4)} />
          {chain.length > 4 && (
            <p className="mt-1 text-xs text-[color:var(--c2-fg-muted)]">+ {chain.length - 4} more step(s) — see the Behavior finding above.</p>
          )}
        </div>
      )}
      {modality.arms?.length > 0 && (
        <ul className="mt-auto flex flex-col gap-1 border-t border-[color:var(--c2-border)] pt-2">
          {modality.arms.map((arm) => (
            <li key={arm.arm} className="flex flex-wrap items-center justify-between gap-2 text-xs">
              <span className="text-[color:var(--c2-fg-2)]">{arm.display || ARM_LABELS[arm.arm] || arm.arm}</span>
              <span className="font-mono text-[color:var(--c2-fg)]">
                {arm.status === 'ok' ? (
                  <>
                    {CLASS_LABELS[arm.predicted] || arm.predicted}
                    {arm.probabilities?.[arm.predicted] !== undefined && ` ${(arm.probabilities[arm.predicted] * 100).toFixed(0)}%`}
                    {arm.fusion_weight !== null && arm.fusion_weight !== undefined && (
                      <span className="text-[color:var(--c2-fg-muted)]"> · w {arm.fusion_weight.toFixed(2)}</span>
                    )}
                  </>
                ) : (
                  <span className="text-[color:var(--c2-sus-hi)]">{arm.status}{arm.reason ? `: ${arm.reason}` : ''}</span>
                )}
              </span>
            </li>
          ))}
        </ul>
      )}
    </article>
  )
}
