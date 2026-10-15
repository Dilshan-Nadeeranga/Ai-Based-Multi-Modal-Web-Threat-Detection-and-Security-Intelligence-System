import { Gauge } from 'lucide-react'
import { LEVEL_STYLES, pct } from './constants.js'
import { Bar, Card } from './ui.jsx'

const LABELS = { text: 'Post text', ocr: 'OCR text', visual: 'Visual threat (CLIP)', website: 'Website dissimilarity', brand: 'Brand similarity' }

export default function RiskBreakdown({ risk }) {
  if (!risk) return null
  const style = LEVEL_STYLES[risk.level]
  return (
    <Card title="Risk breakdown" subtitle="Weighted fusion of available components + consistency boosts" icon={Gauge}>
      <div className="grid md:grid-cols-2 gap-6">
        <div className="space-y-3">
          {Object.entries(LABELS).map(([key, label]) => {
            const value = risk.components[key]
            const weight = risk.weights[key]
            const used = risk.components_used.includes(key)
            const caption = key === 'brand' ? 'used only if a brand mismatch is detected'
              : used ? `weight ${weight} (renormalised over available components)` : 'not available — excluded'
            return value === null || value === undefined
              ? <p key={key} className="text-xs text-slate-500">{label}: not available</p>
              : <Bar key={key} label={label} value={value} hint={caption} />
          })}
        </div>
        <div className="rounded-lg bg-slate-950/60 border border-slate-800 p-4 text-sm space-y-2 font-mono">
          <p className="flex justify-between"><span className="text-slate-400">Weighted base</span><span>{pct(risk.base, 1)}</span></p>
          <p className="flex justify-between"><span className="text-slate-400">Consistency boost</span><span>+{pct(risk.boost, 1)}</span></p>
          <p className={`flex justify-between border-t border-slate-800 pt-2 font-bold ${style.text}`}><span>Final score</span><span>{pct(risk.score, 1)} → {risk.level}</span></p>
          {risk.reasons.length > 0 && <p className="text-xs text-slate-400 font-sans">{risk.reasons.join('; ')}</p>}
          <p className="text-[11px] text-slate-500 font-sans">HIGH {risk.rule.HIGH} · MEDIUM {risk.rule.MEDIUM} · LOW {risk.rule.LOW}</p>
        </div>
      </div>
    </Card>
  )
}
