// Small presentational helpers shared by the social-visual result cards.
import { pct } from './constants.js'

export function Card({ title, subtitle, children, className = '', icon: Icon, id }) {
  return (
    <section id={id} className={`st-fade-up scroll-mt-36 bg-white rounded-xl p-6 shadow-sm ring-1 ring-st-container/60 transition-shadow duration-300 hover:shadow-md ${className}`}>
      {title && (
        <header className="mb-4">
          <h2 className="flex items-center gap-2 font-manrope text-base font-bold text-st-navy">
            {Icon && <Icon className="w-5 h-5 text-st-blue-dark" />} {title}
          </h2>
          {subtitle && <p className="mt-1 text-xs text-st-muted">{subtitle}</p>}
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
      <div className="flex justify-between text-xs text-st-ink">
        <span className="truncate pr-2">{label}</span>
        <span className="font-mono">{pct(value, 1)}</span>
      </div>
      <div className="mt-1 h-2 rounded bg-st-container overflow-hidden">
        <div className={`st-bar h-full rounded ${colour}`} style={{ width: `${width}%` }} />
      </div>
      {hint && <p className="mt-1 text-[11px] text-st-muted">{hint}</p>}
    </div>
  )
}

export function Field({ label, children, mono = false }) {
  return (
    <div className="min-w-0">
      <p className="text-[11px] uppercase tracking-wide text-st-muted">{label}</p>
      <p className={`mt-0.5 text-sm text-st-ink break-words ${mono ? 'font-mono' : ''}`}>{children ?? '—'}</p>
    </div>
  )
}

export function NotAvailable({ children }) {
  return <p className="text-sm text-st-muted italic">{children}</p>
}

export function Check({ ok, children }) {
  return (
    <li className="flex gap-2 text-sm">
      <span className={`st-pop ${ok ? 'text-emerald-700' : 'text-red-700'}`}>{ok ? '✓' : '✕'}</span>
      <span className="text-st-ink">{children}</span>
    </li>
  )
}
