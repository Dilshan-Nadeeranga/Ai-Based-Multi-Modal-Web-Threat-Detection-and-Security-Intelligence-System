import Logo from '../../../components/Logo.jsx'

export function AuthLayout({ title, subtitle, children, footer }) {
  return (
    <main className="flex-1 flex items-center justify-center px-4 py-12 bg-slate-950 text-slate-100">
      <div className="w-full max-w-md">
        <div className="flex items-center justify-center mb-6">
          <Logo onDark className="h-10" />
        </div>
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-8 shadow-xl backdrop-blur-sm">
          <h1 className="text-xl font-semibold text-slate-100">{title}</h1>
          {subtitle && <p className="mt-1 mb-6 text-sm text-slate-400">{subtitle}</p>}
          {children}
        </div>
        {footer && <p className="mt-6 text-center text-sm text-slate-400">{footer}</p>}
      </div>
    </main>
  )
}

export function FormField({ id, label, error, ...inputProps }) {
  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="block text-xs font-semibold uppercase tracking-wide text-slate-400">
        {label}
      </label>
      <input
        id={id}
        className={`w-full rounded-lg bg-slate-950 border px-3.5 py-2.5 text-sm text-slate-100 placeholder-slate-600
          outline-none transition-colors focus:border-sky-500 disabled:opacity-60
          ${error ? 'border-red-500/70' : 'border-slate-700'}`}
        aria-invalid={Boolean(error)}
        aria-describedby={error ? `${id}-error` : undefined}
        {...inputProps}
      />
      {error && <p id={`${id}-error`} className="text-xs text-red-400">{error}</p>}
    </div>
  )
}

export function FormAlert({ children, tone = 'error' }) {
  if (!children) return null
  const styles = tone === 'success'
    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
    : 'bg-red-500/10 border-red-500/30 text-red-300'
  return (
    <div role={tone === 'error' ? 'alert' : 'status'} className={`rounded-lg border px-3.5 py-2.5 text-sm ${styles}`}>
      {children}
    </div>
  )
}

export function SubmitButton({ loading, children, loadingText }) {
  return (
    <button
      type="submit"
      disabled={loading}
      className="w-full rounded-lg bg-sky-600 hover:bg-sky-500 disabled:bg-sky-900 disabled:text-slate-400
        px-4 py-2.5 text-sm font-semibold text-white transition-colors"
    >
      {loading ? loadingText : children}
    </button>
  )
}