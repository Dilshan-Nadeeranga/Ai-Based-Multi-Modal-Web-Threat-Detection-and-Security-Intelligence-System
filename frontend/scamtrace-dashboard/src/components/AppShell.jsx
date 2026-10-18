import { Fragment, useState } from 'react'
import { Link, NavLink, useLocation, useNavigate } from 'react-router-dom'
import {
  ChevronDown,
  ChevronRight,
  FolderGit2,
  History,
  Images,
  LayoutGrid,
  LogOut,
  Menu,
  Plus,
  Radar,
  ScanSearch,
  ShieldCheck,
  UserRound,
  X,
} from 'lucide-react'
import { useAuth } from '../features/auth/hooks/useAuth.js'
import { useProjects } from '../features/code-audit/hooks/useProjects.js'
import Logo from './Logo.jsx'

const NAV_LINKS = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutGrid },
  { to: '/url-analyzer', label: 'Threat Analysis', icon: ScanSearch },
  { to: '/c2', label: 'C2 · Content & Behavior', icon: Radar },
  { to: '/social-visual-analysis', label: 'Social Visual Analysis', icon: Images },
  { to: '/code-audit', label: 'Repository Audit', projects: true },
  { to: '/history', label: 'History', icon: History },
  { to: '/profile', label: 'Profile', icon: UserRound },
]

const SIDEBAR_PROJECT_LIMIT = 2

function navClass({ isActive }) {
  return `group flex items-center gap-2.5 rounded-lg px-3 py-2 text-sm font-semibold transition ${
    isActive ? 'bg-st-navy-2 text-white shadow-sm' : 'text-st-muted hover:bg-st-container hover:text-st-navy'
  }`
}

function subLinkClass(active) {
  return `flex items-center gap-2 rounded-md px-2 py-1.5 text-[0.8125rem] font-medium transition ${
    active ? 'bg-st-container text-st-navy' : 'text-st-muted hover:bg-st-low hover:text-st-navy'
  }`
}

function ProjectsNav({ label, to, onNavigate }) {
  const { pathname } = useLocation()
  const inAudit = pathname.startsWith('/code-audit')
  const [open, setOpen] = useState(inAudit)
  const { projects, loading, error } = useProjects({ enabled: open })
  const currentScan = pathname.startsWith('/code-audit/scans/')
    ? decodeURIComponent(pathname.slice('/code-audit/scans/'.length))
    : null
  const shown = projects?.slice(0, SIDEBAR_PROJECT_LIMIT) || []

  return (
    <div>
      <div className="flex items-center gap-1">
        <NavLink to={to} className={() => `${navClass({ isActive: inAudit })} flex-1`} onClick={onNavigate}>
          <span>{label}</span>
        </NavLink>
        <button
          type="button"
          onClick={() => setOpen((value) => !value)}
          className="rounded-md p-1.5 text-st-muted transition hover:bg-st-container hover:text-st-navy"
          aria-expanded={open}
          aria-controls="sidebar-projects"
          aria-label={open ? 'Hide projects' : 'Show projects'}
        >
          <ChevronDown className={`h-4 w-4 transition-transform ${open ? '' : '-rotate-90'}`} aria-hidden="true" />
        </button>
      </div>

      {open && (
        <div id="sidebar-projects" className="ml-[1.375rem] mt-1 flex flex-col gap-0.5 border-l border-st-container pl-2">
          <NavLink to="/code-audit" end className={({ isActive }) => subLinkClass(isActive)} onClick={onNavigate}>
            <Plus className="h-3.5 w-3.5 shrink-0" aria-hidden="true" /> New Audit
          </NavLink>
          <span className="mt-1.5 px-2 text-[0.625rem] font-bold uppercase tracking-wider text-st-outline">Projects</span>
          {loading && <span className="px-2 py-1 text-xs text-st-outline">Loading…</span>}
          {error && <span className="px-2 py-1 text-xs text-st-error">Projects unavailable</span>}
          {projects?.length === 0 && <span className="px-2 py-1 text-xs text-st-outline">No projects yet</span>}
          {shown.map((project) => (
            <Link
              key={project.repository_url}
              to={`/code-audit/scans/${encodeURIComponent(project.latest_scan_id)}`}
              className={subLinkClass(project.scans.some((scan) => scan.scan_id === currentScan))}
              title={project.repository_url}
              onClick={onNavigate}
            >
              <FolderGit2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              <span className="truncate">{project.name}</span>
            </Link>
          ))}
          {projects?.length > SIDEBAR_PROJECT_LIMIT && (
            <Link to="/code-audit" className="px-2 py-1 text-xs font-semibold text-st-blue-dark hover:underline" onClick={onNavigate}>
              View all {projects.length} projects
            </Link>
          )}
        </div>
      )}
    </div>
  )
}

function Sidebar({ onNavigate }) {
  const { isAdmin, logout } = useAuth()
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
      <div className="flex min-h-0 flex-1 flex-col overflow-y-auto">
        <div className="flex h-[70px] items-center px-5">
          <Link to="/" aria-label="ScamTrace home" onClick={onNavigate}>
            <Logo className="h-9" />
          </Link>
        </div>
        <nav className="flex flex-col gap-1 px-4 py-2" aria-label="Main navigation">
          <span className="mb-1 px-2 text-[0.6875rem] font-bold uppercase tracking-wider text-st-outline">Navigation</span>
          {links.map(({ to, label, icon: Icon, end, projects }) => projects ? (
            <ProjectsNav key={to} to={to} label={label} onNavigate={onNavigate} />
          ) : (
            <NavLink key={to} to={to} end={end} className={navClass} onClick={onNavigate}>
              <Icon className="h-[18px] w-[18px] shrink-0" aria-hidden="true" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
      </div>

      <div className="p-4">
        <button
          type="button"
          onClick={handleLogout}
          disabled={leaving}
          className="flex w-full items-center justify-center gap-2 rounded-lg bg-st-error px-3 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-[#93000a] disabled:opacity-60"
        >
          <LogOut className="h-4 w-4" aria-hidden="true" /> {leaving ? 'Signing out…' : 'Logout'}
        </button>
      </div>
    </div>
  )
}

/**
 * Light sidebar layout for signed-in pages. The header breadcrumb is
 * Dashboard > [section] > title, e.g. Dashboard > Code Audit > NodeGoat.
 */
export default function AppShell({ title, section, children }) {
  const { user } = useAuth()
  const [menuOpen, setMenuOpen] = useState(false)
  const crumbs = [
    { label: 'Dashboard', to: '/dashboard' },
    ...(section && section.label !== title ? [section] : []),
    ...(title !== 'Dashboard' ? [{ label: title }] : []),
  ]

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
            <nav aria-label="Breadcrumb" className="flex min-w-0 items-center gap-1 text-xs font-semibold text-st-outline">
              {crumbs.map((crumb, index) => (
                <Fragment key={crumb.label}>
                  {index > 0 && <ChevronRight className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />}
                  {index < crumbs.length - 1 ? (
                    <Link to={crumb.to} className="shrink-0 font-bold text-st-navy hover:underline">{crumb.label}</Link>
                  ) : (
                    <span className="truncate text-st-ink" aria-current="page">{crumb.label}</span>
                  )}
                </Fragment>
              ))}
            </nav>
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
