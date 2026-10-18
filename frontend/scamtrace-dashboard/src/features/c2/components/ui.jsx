import { useState } from 'react'
import { AlertTriangle, Check, Copy, Inbox, Loader2, RefreshCw } from 'lucide-react'
import { defangUrl } from '../api/defang.js'

/** Dark console panel with a mono section label. */
export function Panel({ title, icon: Icon, actions, children, className = '', as: Tag = 'section' }) {
  return (
    <Tag className={`c2-panel rounded-xl border border-slate-800 p-4 shadow-[0_0_0_1px_rgba(34,211,238,0.03)] ${className}`}>
      {(title || actions) && (
        <header className="mb-3 flex items-center justify-between gap-3">
          {title && (
            <h2 className="flex items-center gap-2 font-mono text-xs font-semibold uppercase tracking-[0.14em] text-cyan-300">
              {Icon && <Icon className="h-4 w-4" aria-hidden="true" />}
              {title}
            </h2>
          )}
          {actions}
        </header>
      )}
      {children}
    </Tag>
  )
}

export function Chip({ children, tone = 'slate', className = '', title }) {
  const tones = {
    slate: 'bg-slate-800/80 text-slate-200 ring-slate-600/60',
    cyan: 'bg-cyan-400/10 text-cyan-200 ring-cyan-400/40',
    amber: 'bg-amber-400/10 text-amber-200 ring-amber-400/40',
    red: 'bg-red-500/10 text-red-200 ring-red-400/50',
    green: 'bg-emerald-400/10 text-emerald-200 ring-emerald-400/40',
  }
  return (
    <span title={title} className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 font-mono text-xs ring-1 ${tones[tone]} ${className}`}>
      {children}
    </span>
  )
}

/** Loading / empty / error states, used by every view. */
export function StateBox({ state, message, onRetry, children }) {
  const config = {
    loading: { icon: Loader2, tone: 'text-cyan-300', text: message || 'Loading…', spin: true },
    empty: { icon: Inbox, tone: 'text-slate-400', text: message || 'Nothing here yet.' },
    error: { icon: AlertTriangle, tone: 'text-amber-300', text: message || 'Something went wrong.' },
  }[state]
  const Icon = config.icon
  return (
    <div role={state === 'error' ? 'alert' : 'status'} className="flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-slate-700 px-4 py-10 text-center">
      <Icon className={`h-6 w-6 ${config.tone} ${config.spin ? 'animate-spin motion-reduce:animate-none' : ''}`} aria-hidden="true" />
      <p className="max-w-md text-sm text-slate-300">{config.text}</p>
      {children}
      {onRetry && (
        <button type="button" onClick={onRetry} className="inline-flex items-center gap-1.5 rounded-md border border-slate-600 px-3 py-1.5 text-sm text-slate-200 hover:border-cyan-400 hover:text-cyan-200">
          <RefreshCw className="h-4 w-4" aria-hidden="true" /> Try again
        </button>
      )}
    </div>
  )
}

export function CopyButton({ value, label = 'Copy' }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      setCopied(false)
    }
  }
  return (
    <button
      type="button"
      onClick={copy}
      className="inline-flex shrink-0 items-center gap-1 rounded-md border border-slate-700 px-1.5 py-0.5 text-xs text-slate-300 hover:border-cyan-400 hover:text-cyan-200"
      aria-label={copied ? 'Copied' : `${label} (defanged)`}
      title="Copies the defanged text (not a clickable link)"
    >
      {copied ? <Check className="h-3.5 w-3.5" aria-hidden="true" /> : <Copy className="h-3.5 w-3.5" aria-hidden="true" />}
      <span className="sr-only sm:not-sr-only">{copied ? 'Copied' : label}</span>
    </button>
  )
}

/** A scan URL as defanged plain text + copy button. Never a link. */
export function DefangedUrl({ url, className = '', copy = true }) {
  const shown = defangUrl(url) || '—'
  return (
    <span className={`inline-flex min-w-0 max-w-full items-center gap-2 ${className}`}>
      <span className="truncate font-mono text-sm text-cyan-100" title={shown}>
        {shown}
      </span>
      {copy && url && <CopyButton value={shown} />}
    </span>
  )
}

export function SegmentedControl({ label, options, value, onChange }) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex rounded-lg border border-slate-700 bg-slate-900 p-0.5">
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          role="radio"
          aria-checked={value === option.value}
          onClick={() => onChange(option.value)}
          className={`rounded-md px-3 py-1 text-sm font-medium ${
            value === option.value ? 'bg-cyan-400/15 text-cyan-200 ring-1 ring-cyan-400/40' : 'text-slate-300 hover:text-white'
          }`}
        >
          {option.label}
        </button>
      ))}
    </div>
  )
}

export function SelectField({ id, label, value, onChange, options }) {
  return (
    <label htmlFor={id} className="flex flex-col gap-1 text-xs font-medium text-slate-400">
      {label}
      <select
        id={id}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1.5 text-sm text-slate-100 focus:border-cyan-400"
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  )
}
