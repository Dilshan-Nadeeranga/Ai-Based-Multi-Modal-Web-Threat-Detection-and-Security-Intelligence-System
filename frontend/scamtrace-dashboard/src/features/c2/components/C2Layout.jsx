import { Suspense } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { Activity, FlaskConical, History, Moon, Radar, ScanSearch, Sun } from 'lucide-react'
import AppShell from '../../../components/AppShell.jsx'
import { C2_BASE_URL } from '../api/c2Api.js'
import DemoModeProvider from '../context/DemoModeProvider.jsx'
import { useC2Theme } from '../hooks/useC2Theme.js'
import { useDemoMode } from '../hooks/useDemoMode.js'
import { StateBox } from './ui.jsx'
import '../c2.css'

const TABS = [
  { to: '/c2', label: 'Scan', icon: ScanSearch, end: true },
  { to: '/c2/feed', label: 'Live Threat Feed', icon: Activity },
  { to: '/c2/research', label: 'Research', icon: FlaskConical },
  { to: '/c2/history', label: 'History', icon: History },
]

const BACKEND = {
  checking: { text: 'checking C2…', dot: 'bg-[color:var(--c2-neutral-solid)]' },
  online: { text: 'C2 API online', dot: 'bg-[color:var(--c2-ok-solid)]' },
  loading: { text: 'C2 loading models…', dot: 'bg-[color:var(--c2-sus-dot)]' },
  degraded: { text: 'C2 models not usable', dot: 'bg-[color:var(--c2-sus-dot)]' },
  offline: { text: 'C2 API offline', dot: 'bg-[color:var(--c2-mal-solid)]' },
}

function DemoSwitch() {
  const { demo, setDemo } = useDemoMode()
  return (
    <label className="flex cursor-pointer items-center gap-2 text-sm text-[color:var(--c2-fg)]">
      <span>Demo mode</span>
      <button
        type="button"
        role="switch"
        aria-checked={demo}
        onClick={() => setDemo(!demo)}
        className={`relative h-6 w-11 rounded-full ring-1 transition ${demo ? 'bg-[color:var(--c2-switch-on)] ring-[color:var(--c2-switch-on-ring)]' : 'bg-[color:var(--c2-switch-off)] ring-[color:var(--c2-switch-off-ring)]'}`}
      >
        <span className={`absolute top-0.5 h-5 w-5 rounded-full bg-white shadow transition-all ${demo ? 'left-[1.375rem]' : 'left-0.5'}`} />
        <span className="sr-only">Use bundled demo data</span>
      </button>
    </label>
  )
}

function ThemeSwitch({ theme, onChange }) {
  const dark = theme === 'dark'
  return (
    <div className="flex items-center gap-2 text-sm text-[color:var(--c2-fg)]">
      <span aria-hidden="true" className={dark ? 'text-[color:var(--c2-fg-faint)]' : 'font-medium'}>Light</span>
      <button
        type="button"
        role="switch"
        aria-checked={dark}
        aria-label="Dark theme"
        onClick={() => onChange(dark ? 'light' : 'dark')}
        className={`relative h-6 w-11 rounded-full ring-1 transition ${dark ? 'bg-[color:var(--c2-accent-80)] ring-[color:var(--c2-accent-ring)]' : 'bg-[color:var(--c2-switch-off)] ring-[color:var(--c2-switch-off-ring)]'}`}
      >
        <span className={`absolute top-0.5 flex h-5 w-5 items-center justify-center rounded-full bg-white text-slate-700 shadow transition-all ${dark ? 'left-[1.375rem]' : 'left-0.5'}`}>
          {dark ? <Moon className="h-3 w-3" aria-hidden="true" /> : <Sun className="h-3 w-3" aria-hidden="true" />}
        </span>
      </button>
      <span aria-hidden="true" className={dark ? 'font-medium' : 'text-[color:var(--c2-fg-faint)]'}>Dark</span>
    </div>
  )
}

function SectionHeader({ theme, onThemeChange }) {
  const { demo, reason, backend, recheck } = useDemoMode()
  const status = BACKEND[backend.state] || BACKEND.checking
  const xlmr = backend.ready?.xlmr_enabled
  return (
    <div className="border-b border-[color:var(--c2-border)] bg-[color:var(--c2-header-bg)]">
      <div className="mx-auto flex max-w-[1400px] flex-wrap items-center justify-between gap-3 px-4 pt-4 md:px-6">
        <div className="flex items-center gap-3">
          <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-[color:var(--c2-accent-tint)] text-[color:var(--c2-accent)] ring-1 ring-[color:var(--c2-accent-ring)]">
            <Radar className="h-5 w-5" aria-hidden="true" />
          </span>
          <div>
            <h1 className="font-mono text-lg font-semibold tracking-tight text-[color:var(--c2-fg-strong)]">C2 · Content &amp; Behavior</h1>
            <p className="text-xs text-[color:var(--c2-fg-muted)]">DOM structure · multilingual text (en / si / ta) · static JS behavior → one verdict</p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-4">
          <button
            type="button"
            onClick={recheck}
            className="flex items-center gap-2 rounded-md px-2 py-1 font-mono text-xs text-[color:var(--c2-fg-2)] hover:bg-[color:var(--c2-hover)]"
            title={`${C2_BASE_URL}${backend.detail ? ` — ${backend.detail}` : ''} (click to re-check)`}
          >
            <span className={`h-2 w-2 rounded-full ${status.dot}`} aria-hidden="true" />
            {status.text}
            {backend.state === 'online' && xlmr !== undefined && <span className="text-[color:var(--c2-fg-faint)]">· {xlmr ? '4 arms' : '3 arms'}</span>}
          </button>
          <ThemeSwitch theme={theme} onChange={onThemeChange} />
          <DemoSwitch />
        </div>
      </div>
      <nav className="mx-auto flex max-w-[1400px] gap-1 overflow-x-auto px-4 md:px-6" aria-label="C2 sections">
        {TABS.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              `flex items-center gap-2 whitespace-nowrap border-b-2 px-3 py-2.5 text-sm font-medium ${
                isActive ? 'border-[color:var(--c2-accent-solid)] text-[color:var(--c2-accent-hi)]' : 'border-transparent text-[color:var(--c2-fg-muted)] hover:text-[color:var(--c2-fg-hi)]'
              }`
            }
          >
            <Icon className="h-4 w-4" aria-hidden="true" />
            {label}
          </NavLink>
        ))}
      </nav>
      {demo && (
        <div role="status" className="border-t border-[color:var(--c2-sus-ring-soft)] bg-[color:var(--c2-sus-tint)]">
          <p className="mx-auto max-w-[1400px] px-4 py-1.5 font-mono text-xs text-[color:var(--c2-sus-ink)] md:px-6">
            <strong className="mr-2 rounded bg-[color:var(--c2-demo-chip-bg)] px-1.5 py-0.5 text-[color:var(--c2-demo-chip-fg)]">DEMO DATA</strong>
            {reason === 'auto'
              ? `C2 API not available (${backend.detail || 'offline'}) — showing recorded C2 results bundled with the dashboard.`
              : 'Showing recorded C2 results bundled with the dashboard (real model output, captured earlier).'}
          </p>
        </div>
      )}
    </div>
  )
}

/** C2 section: team AppShell → C2 area with its own tabs; light by default, dark console optional. */
export default function C2Layout() {
  const [theme, setTheme] = useC2Theme()
  return (
    <AppShell title="C2 · Content & Behavior">
      <DemoModeProvider>
        <div className="c2-console min-h-[calc(100vh-70px)] font-inter" data-c2-theme={theme}>
          <SectionHeader theme={theme} onThemeChange={setTheme} />
          <div className="mx-auto max-w-[1400px] px-4 py-5 md:px-6">
            <Suspense fallback={<StateBox state="loading" message="Loading…" />}>
              <Outlet />
            </Suspense>
          </div>
        </div>
      </DemoModeProvider>
    </AppShell>
  )
}
