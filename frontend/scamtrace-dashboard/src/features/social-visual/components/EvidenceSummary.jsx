import { ClipboardList, ShieldAlert, ShieldCheck } from 'lucide-react'
import { LEVEL_STYLES } from './constants.js'
import { Card, Check } from './ui.jsx'

export default function EvidenceSummary({ assessment }) {
  const style = LEVEL_STYLES[assessment.level] || LEVEL_STYLES.LOW
  const Icon = assessment.level === 'LOW' ? ShieldCheck : ShieldAlert
  return (
    <Card title="Why was this post flagged?" icon={ClipboardList}>
      <ul className="space-y-1.5">
        {assessment.evidence.map((line, i) => <Check key={i} ok={line.ok}>{line.text}</Check>)}
        {assessment.evidence.length === 0 && <li className="text-sm text-st-muted">No evidence lines produced.</li>}
      </ul>
      <div className={`st-fade-up mt-5 flex items-start gap-3 rounded-lg border ${style.border} ${style.soft} p-4`}>
        <Icon className={`mt-0.5 h-6 w-6 shrink-0 ${style.text}`} aria-hidden="true" />
        <div>
          <p className="text-[11px] font-bold uppercase tracking-widest text-st-muted">Conclusion · risk {assessment.level}</p>
          <p className={`mt-1 text-base font-semibold leading-snug ${style.text}`}>{assessment.conclusion}</p>
        </div>
      </div>
    </Card>
  )
}
