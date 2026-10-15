import { ClipboardList } from 'lucide-react'
import { LEVEL_STYLES } from './constants.js'
import { Card, Check } from './ui.jsx'

export default function EvidenceSummary({ assessment }) {
  const style = LEVEL_STYLES[assessment.level]
  return (
    <Card title="Why was this post flagged?" icon={ClipboardList}>
      <ul className="space-y-1.5">
        {assessment.evidence.map((line, i) => <Check key={i} ok={line.ok}>{line.text}</Check>)}
        {assessment.evidence.length === 0 && <li className="text-sm text-slate-500">No evidence lines produced.</li>}
      </ul>
      <p className={`mt-4 border-t border-slate-800 pt-3 font-semibold ${style.text}`}>Conclusion: {assessment.conclusion}</p>
    </Card>
  )
}
