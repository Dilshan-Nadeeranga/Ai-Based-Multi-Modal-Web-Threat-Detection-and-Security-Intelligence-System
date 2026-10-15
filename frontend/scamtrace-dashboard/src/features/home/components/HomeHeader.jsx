import { Link } from 'react-router-dom'
import { LayoutDashboard, Radar } from 'lucide-react'
import Logo from '../../../components/Logo.jsx'
import { useAuth } from '../../auth/hooks/useAuth.js'

const SECTION_LINKS = [
  { hash: '#top', label: 'Home' },
  { hash: '#threats', label: 'Threats' },
  { hash: '#how-it-works', label: 'How It Works' },
  { hash: '#modules', label: 'Modules' },
  { hash: '#research', label: 'Research' },
]

export default function HomeHeader() {
  const { user, loading } = useAuth()

  return (
    <header className="fixed top-0 z-50 w-full border-b border-st-container bg-white/95 shadow-[0_2px_12px_rgba(7,28,140,0.08)] backdrop-blur-md">
      <div className="mx-auto flex h-20 w-full max-w-7xl items-center justify-between gap-4 px-4 lg:px-12">
        <Link to={{ pathname: '/', hash: '#top' }} aria-label="ScamTrace home">
          <Logo className="h-10" />
        </Link>

        <nav className="hidden items-center gap-1 lg:flex" aria-label="Home page sections">
          {SECTION_LINKS.map((link) => (
            <Link
              key={link.hash}
              to={{ pathname: '/', hash: link.hash }}
              className="rounded-lg px-4 py-2 text-sm font-semibold text-st-muted transition-all hover:bg-st-low hover:text-st-ink"
            >
              {link.label}
            </Link>
          ))}
        </nav>

        <div className="flex items-center gap-3">
          {!loading && !user && (
            <>
              <Link to="/login" className="hidden px-2 py-1 text-sm font-semibold text-st-navy transition-colors hover:text-st-blue-dark sm:inline-flex">
                Login
              </Link>
              <Link
                to="/register"
                className="inline-flex items-center gap-1.5 rounded-xl bg-st-blue px-5 py-2.5 text-sm font-semibold text-white shadow-[0_4px_14px_rgba(7,28,140,0.2)] transition-all hover:bg-st-navy-2 hover:shadow-[0_6px_20px_rgba(7,28,140,0.3)]"
              >
                <Radar className="h-4 w-4" aria-hidden="true" />
                Get Started
              </Link>
            </>
          )}
          {!loading && user && (
            <>
              <span className="hidden text-sm font-medium text-st-muted sm:inline">{user.name}</span>
              <Link
                to="/dashboard"
                className="inline-flex items-center gap-1.5 rounded-xl bg-st-blue px-5 py-2.5 text-sm font-semibold text-white shadow-[0_4px_14px_rgba(7,28,140,0.2)] transition-all hover:bg-st-navy-2"
              >
                <LayoutDashboard className="h-4 w-4" aria-hidden="true" />
                Dashboard
              </Link>
            </>
          )}
        </div>
      </div>
    </header>
  )
}
