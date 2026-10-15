// Small presentational helpers shared by the social-visual result cards.
import { pct } from './constants.js'

export function Card({ title, subtitle, children, className = '', icon: Icon }) {
  return (
    <section className={`bg-slate-900/80 border border-slate-800 rounded-xl p-6 ${className}`}>
      {title && (
        <header className="mb-4">
          <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-slate-300">
            {Icon && <Icon className="w-4 h-4 text-sky-400" />} {title}
          </h2>
          {subtitle && <p className="mt-1 text-xs text-slate-500">{subtitle}</p>}
        </header>
      )}
      {children}
    </section>
  )
}

export function Bar({ label, value, tone, hint }) {
  const width = value === null || value === undefined ? 0 : Math.max(0, Math.min(1, value)) * 100
  const colour = tone || (value >= 0.7 ? 'bg-red-500' : value >= 0.4 ? 'bg-orange-500' : 'bg-emerald-500')
  return (
    <div>
      <div className="flex justify-between text-xs text-slate-300">
        <span className="truncate pr-2">{label}</span>
        <span className="font-mono">{pct(value, 1)}</span>
      </div>
      <div className="mt-1 h-2 rounded bg-slate-800 overflow-hidden">
        <div className={`h-full ${colour}`} style={{ width: `${width}%` }} />
      </div>
      {hint && <p className="mt-1 text-[11px] text-slate-500">{hint}</p>}
    </div>
  )
}

export function Field({ label, children, mono = false }) {
  return (
    <div className="min-w-0">
      <p className="text-[11px] uppercase tracking-wide text-slate-500">{label}</p>
      <p className={`mt-0.5 text-sm text-slate-200 break-words ${mono ? 'font-mono' : ''}`}>{children ?? '—'}</p>
    </div>
  )
}

export function NotAvailable({ children }) {
  return <p className="text-sm text-slate-500 italic">{children}</p>
}

export function Check({ ok, children }) {
  return (
    <li className="flex gap-2 text-sm">
      <span className={ok ? 'text-emerald-400' : 'text-red-400'}>{ok ? '✓' : '✕'}</span>
      <span className="text-slate-200">{children}</span>
    </li>
  )
}
