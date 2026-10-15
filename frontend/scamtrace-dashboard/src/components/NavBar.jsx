import { useState } from 'react'
import { Link, NavLink, useNavigate } from 'react-router-dom'
import { LogOut, ShieldCheck } from 'lucide-react'
import { useAuth } from '../features/auth/hooks/useAuth.js'

const USER_LINKS = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/url-analyzer', label: 'Threat Analysis' },
  { to: '/social-visual-analysis', label: 'Social Visual Analysis' },
  { to: '/code-audit', label: 'Repository Audit', end: true },
  { to: '/history', label: 'History' },
  { to: '/profile', label: 'Profile' },
]

function linkClass({ isActive }) {
  return `px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${isActive
    ? 'bg-slate-800 text-white' : 'text-slate-300 hover:text-white hover:bg-slate-800/60'}`
}

export default function NavBar() {
  const { user, isAdmin, loading, logout } = useAuth()
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

  return (
    <header className="w-full border-b border-slate-800 bg-slate-950/95 backdrop-blur sticky top-0 z-40">
      <nav className="max-w-7xl mx-auto px-4 py-2 min-h-14 flex flex-wrap items-center gap-x-4 gap-y-2">
        <Link to={user ? '/dashboard' : '/'} className="flex items-center gap-2 text-slate-100 font-bold tracking-tight">
          <ShieldCheck className="w-5 h-5 text-sky-400" /> ScamTrace
        </Link>

        {!loading && user && (
          <div className="flex flex-1 flex-wrap items-center gap-1">
            {USER_LINKS.map((link) => (
              <NavLink key={link.to} to={link.to} end={link.end} className={linkClass}>{link.label}</NavLink>
            ))}
            {isAdmin && <NavLink to="/admin" className={linkClass}>Admin Dashboard</NavLink>}
          </div>
        )}
        {!loading && !user && <div className="flex-1" />}

        {!loading && user && (
          <div className="flex items-center gap-3">
            <span className="hidden sm:inline text-sm text-slate-300">
              {user.name}
              {isAdmin && <span className="ml-2 text-xs font-semibold text-purple-300">ADMIN</span>}
            </span>
            <button type="button" onClick={handleLogout} disabled={leaving}
                    className="flex items-center gap-1.5 rounded-md border border-slate-700 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-800">
              <LogOut className="w-4 h-4" /> Logout
            </button>
          </div>
        )}
        {!loading && !user && (
          <div className="flex items-center gap-2">
            <NavLink to="/login" className={linkClass}>Login</NavLink>
            <Link to="/register" className="rounded-md bg-sky-600 hover:bg-sky-500 px-3 py-1.5 text-sm font-semibold text-white">
              Register
            </Link>
          </div>
        )}
      </nav>
    </header>
  )
}
