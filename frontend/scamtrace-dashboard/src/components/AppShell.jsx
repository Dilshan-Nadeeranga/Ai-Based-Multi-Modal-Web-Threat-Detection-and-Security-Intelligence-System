import { useState } from 'react'
import { Link, NavLink, useNavigate } from 'react-router-dom'
import {
  ChevronRight,
  Code,
  History,
  Images,
  LayoutGrid,
  LogOut,
  Menu,
  Radar,
  ScanSearch,
  ShieldCheck,
  UserRound,
  X,
} from 'lucide-react'
import { useAuth } from '../features/auth/hooks/useAuth.js'
import Logo from './Logo.jsx'

const NAV_LINKS = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutGrid },
  { to: '/url-analyzer', label: 'Threat Analysis', icon: ScanSearch },
  { to: '/c2', label: 'C2 · Content & Behavior', icon: Radar },
  { to: '/social-visual-analysis', label: 'Social Visual Analysis', icon: Images },
  { to: '/code-audit', label: 'Repository Audit', icon: Code, end: true },
  { to: '/history', label: 'History', icon: History },
  { to: '/profile', label: 'Profile', icon: UserRound },
]

function initials(name = '') {
  const parts = name.trim().split(/\s+/).filter(Boolean)
  return ((parts[0]?.[0] || '') + (parts.length > 1 ? parts[parts.length - 1][0] : '')).toUpperCase() || '?'
}

function navClass({ isActive }) {
  return `group flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-semibold transition ${
    isActive ? 'bg-st-navy-2 text-white shadow-sm' : 'text-st-muted hover:bg-st-container hover:text-st-navy'
  }`
}

function Sidebar({ onNavigate }) {
  const { user, isAdmin, logout } = useAuth()
  const navigate = useNavigate()
  const [leaving, setLeaving] = useState(false)

  async function handleLogout() {
    setLeaving(true)
    try {
      await logout()
    } finally {
      setLeaving(false)
      navigate('/login', { replace: true })
    }
  }

  const links = isAdmin ? [...NAV_LINKS, { to: '/admin', label: 'Admin Dashboard', icon: ShieldCheck }] : NAV_LINKS

  return (
    <div className="flex h-full flex-col justify-between bg-white shadow-[0_1px_8px_rgba(7,28,140,0.06)]">
      <div className="flex flex-col">
        <div className="flex h-[70px] items-center px-5">
          <Link to="/" aria-label="ScamTrace home" onClick={onNavigate}>
            <Logo className="h-9" />
          </Link>
        </div>
        <nav className="flex flex-col gap-1 px-4 py-2" aria-label="Main navigation">
          <span className="mb-1 px-2 text-[0.6875rem] font-bold uppercase tracking-wider text-st-outline">Navigation</span>
          {links.map(({ to, label, icon: Icon, end }) => (
            <NavLink key={to} to={to} end={end} className={navClass} onClick={onNavigate}>
              <Icon className="h-[18px] w-[18px] shrink-0" aria-hidden="true" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
      </div>

      <div className="flex flex-col gap-3 p-4">
        <div className="flex items-center justify-between gap-2 rounded-lg bg-st-low p-2.5">
          <div className="flex min-w-0 items-center gap-2">
            <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-st-navy text-xs font-bold text-white">
              {initials(user?.name)}
            </span>
            <div className="min-w-0 leading-tight">
              <p className="truncate text-xs font-semibold text-st-ink">{user?.name}</p>
              <p className="truncate text-[0.6875rem] text-st-outline">{user?.email}</p>
            </div>
          </div>
          <span className="shrink-0 rounded-full bg-st-fixed px-2 py-0.5 text-[0.625rem] font-bold uppercase tracking-wider text-st-navy">
            {user?.role}
          </span>
        </div>
        <button
          type="button"
          onClick={handleLogout}
          disabled={leaving}
          className="flex items-center justify-center gap-2 rounded-lg bg-st-error px-3 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-[#93000a] disabled:opacity-60"
        >
          <LogOut className="h-4 w-4" aria-hidden="true" /> {leaving ? 'Signing out…' : 'Logout'}
        </button>
      </div>
    </div>
  )
}

/** Light sidebar layout for signed-in pages. */
export default function AppShell({ title, children }) {
  const { user } = useAuth()
  const [menuOpen, setMenuOpen] = useState(false)

  return (
    <div className="min-h-screen bg-st-surface font-inter text-st-ink antialiased selection:bg-st-fixed selection:text-st-navy">
      <aside className="fixed left-0 top-0 z-50 hidden h-screen w-64 lg:block">
        <Sidebar />
      </aside>

      {menuOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <button
            type="button"
            className="absolute inset-0 bg-st-navy/30"
            aria-label="Close menu"
            onClick={() => setMenuOpen(false)}
          />
          <aside className="relative h-full w-64">
            <Sidebar onNavigate={() => setMenuOpen(false)} />
            <button
              type="button"
              onClick={() => setMenuOpen(false)}
              className="absolute right-3 top-5 rounded-lg p-1.5 text-st-muted hover:bg-st-container"
              aria-label="Close menu"
            >
              <X className="h-5 w-5" aria-hidden="true" />
            </button>
          </aside>
        </div>
      )}

      <div className="lg:pl-64">
        <header className="fixed left-0 right-0 top-0 z-40 flex h-[70px] items-center justify-between gap-4 bg-white/90 px-4 shadow-[0_1px_8px_rgba(7,28,140,0.06)] backdrop-blur-xl md:px-8 lg:left-64">
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => setMenuOpen(true)}
              className="rounded-lg p-1.5 text-st-muted hover:bg-st-container lg:hidden"
              aria-label="Open menu"
            >
              <Menu className="h-5 w-5" aria-hidden="true" />
            </button>
            <div className="flex items-center gap-1 text-xs font-semibold text-st-outline">
              <span className="font-bold text-st-navy">ScamTrace</span>
              <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
              <span className="text-st-ink">{title}</span>
            </div>
          </div>
          <Link to="/profile" className="flex items-center gap-2 rounded-lg px-2 py-1 transition hover:bg-st-low">
            <span className="flex h-8 w-8 items-center justify-center rounded-full bg-st-navy text-white">
              <UserRound className="h-4 w-4" aria-hidden="true" />
            </span>
            <span className="hidden flex-col text-left leading-tight md:flex">
              <span className="text-xs font-semibold text-st-ink">{user?.name}</span>
              <span className="text-[0.6875rem] text-st-outline">Signed in</span>
            </span>
          </Link>
        </header>

        <main className="min-h-screen pt-[70px]">{children}</main>
      </div>
    </div>
  )
}
