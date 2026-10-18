import { Suspense } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { Activity, FlaskConical, History, Radar, ScanSearch } from 'lucide-react'
import AppShell from '../../../components/AppShell.jsx'
import { C2_BASE_URL } from '../api/c2Api.js'
import DemoModeProvider from '../context/DemoModeProvider.jsx'
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
  checking: { text: 'checking C2…', dot: 'bg-slate-400' },
  online: { text: 'C2 API online', dot: 'bg-emerald-400' },
  loading: { text: 'C2 loading models…', dot: 'bg-amber-300' },
  degraded: { text: 'C2 models not usable', dot: 'bg-amber-300' },
  offline: { text: 'C2 API offline', dot: 'bg-red-400' },
}

function DemoSwitch() {
  const { demo, setDemo } = useDemoMode()
  return (
    <label className="flex cursor-pointer items-center gap-2 text-sm text-slate-200">
      <span>Demo mode</span>
      <button
        type="button"
        role="switch"
        aria-checked={demo}
        onClick={() => setDemo(!demo)}
        className={`relative h-6 w-11 rounded-full ring-1 transition ${demo ? 'bg-amber-400/80 ring-amber-300' : 'bg-slate-700 ring-slate-600'}`}
      >
        <span className={`absolute top-0.5 h-5 w-5 rounded-full bg-white shadow transition-all ${demo ? 'left-[1.375rem]' : 'left-0.5'}`} />
        <span className="sr-only">Use bundled demo data</span>
      </button>
    </label>
  )
}

function SectionHeader() {
  const { demo, reason, backend, recheck } = useDemoMode()
  const status = BACKEND[backend.state] || BACKEND.checking
  const xlmr = backend.ready?.xlmr_enabled
  return (
    <div className="border-b border-slate-800 bg-slate-950/80">
      <div className="mx-auto flex max-w-[1400px] flex-wrap items-center justify-between gap-3 px-4 pt-4 md:px-6">
        <div className="flex items-center gap-3">
          <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyan-400/10 text-cyan-300 ring-1 ring-cyan-400/40">
            <Radar className="h-5 w-5" aria-hidden="true" />
          </span>
          <div>
            <h1 className="font-mono text-lg font-semibold tracking-tight text-slate-50">C2 · Content &amp; Behavior</h1>
            <p className="text-xs text-slate-400">DOM structure · multilingual text (en / si / ta) · static JS behavior → one verdict</p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-4">
          <button
            type="button"
            onClick={recheck}
            className="flex items-center gap-2 rounded-md px-2 py-1 font-mono text-xs text-slate-300 hover:bg-slate-800"
            title={`${C2_BASE_URL}${backend.detail ? ` — ${backend.detail}` : ''} (click to re-check)`}
          >
            <span className={`h-2 w-2 rounded-full ${status.dot}`} aria-hidden="true" />
            {status.text}
            {backend.state === 'online' && xlmr !== undefined && <span className="text-slate-500">· {xlmr ? '4 arms' : '3 arms'}</span>}
          </button>
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
                isActive ? 'border-cyan-400 text-cyan-200' : 'border-transparent text-slate-400 hover:text-slate-100'
              }`
            }
          >
            <Icon className="h-4 w-4" aria-hidden="true" />
            {label}
          </NavLink>
        ))}
      </nav>
      {demo && (
        <div role="status" className="border-t border-amber-400/30 bg-amber-400/10">
          <p className="mx-auto max-w-[1400px] px-4 py-1.5 font-mono text-xs text-amber-100 md:px-6">
            <strong className="mr-2 rounded bg-amber-300 px-1.5 py-0.5 text-slate-950">DEMO DATA</strong>
            {reason === 'auto'
              ? `C2 API not available (${backend.detail || 'offline'}) — showing recorded C2 results bundled with the dashboard.`
              : 'Showing recorded C2 results bundled with the dashboard (real model output, captured earlier).'}
          </p>
        </div>
      )}
    </div>
  )
}

/** C2 section: team AppShell (light sidebar) → dark console with its own tabs. */
export default function C2Layout() {
  return (
    <AppShell title="C2 · Content & Behavior">
      <DemoModeProvider>
        <div className="c2-console min-h-[calc(100vh-70px)] font-inter">
          <SectionHeader />
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
