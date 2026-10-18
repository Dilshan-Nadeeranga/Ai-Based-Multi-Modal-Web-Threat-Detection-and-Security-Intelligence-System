import { ShieldAlert, ShieldCheck, ShieldQuestion, ShieldX } from 'lucide-react'
import { VERDICT_STYLE } from '../constants.js'

const ICONS = { Legitimate: ShieldCheck, Suspicious: ShieldAlert, Malicious: ShieldX, none: ShieldQuestion }

/** Verdict as icon + word (never colour alone). size: 'sm' | 'lg'. */
export default function VerdictBadge({ verdict, size = 'sm', label }) {
  const key = verdict && VERDICT_STYLE[verdict] ? verdict : 'none'
  const style = VERDICT_STYLE[key]
  const Icon = ICONS[key]
  const large = size === 'lg'
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-lg font-mono font-semibold uppercase tracking-wide ring-1 ${style.bg} ${style.text} ${style.ring} ${
        large ? 'px-4 py-2 text-xl' : 'px-2 py-0.5 text-xs'
      }`}
    >
      <Icon className={large ? 'h-6 w-6' : 'h-3.5 w-3.5'} aria-hidden="true" />
      {label || style.label}
    </span>
  )
}
