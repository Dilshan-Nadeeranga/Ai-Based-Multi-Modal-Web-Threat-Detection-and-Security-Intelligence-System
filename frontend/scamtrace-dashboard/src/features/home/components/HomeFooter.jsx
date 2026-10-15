import { Link } from 'react-router-dom'
import { ShieldCheck } from 'lucide-react'
import Logo from '../../../components/Logo.jsx'

const FOOTER_COLUMNS = [
  {
    title: 'Platform',
    links: [
      { to: '/url-analyzer', label: 'URL & Domain Analysis' },
      { to: '/social-visual-analysis', label: 'Social & Visual Analysis' },
      { to: '/code-audit', label: 'Repository Audit' },
      { to: '/history', label: 'Analysis History' },
    ],
  },
  {
    title: 'Project',
    links: [
      { to: { pathname: '/', hash: '#how-it-works' }, label: 'How It Works' },
      { to: { pathname: '/', hash: '#modules' }, label: 'Analysis Modules' },
      { to: { pathname: '/', hash: '#architecture' }, label: 'Architecture' },
      { to: { pathname: '/', hash: '#research' }, label: 'Research' },
    ],
  },
  {
    title: 'Account',
    links: [
      { to: '/login', label: 'Login' },
      { to: '/register', label: 'Create Account' },
      { to: '/dashboard', label: 'Dashboard' },
      { to: '/profile', label: 'Profile' },
    ],
  },
]

const linkClass = 'text-sm text-st-muted transition-colors hover:text-st-navy'

export default function HomeFooter() {
  return (
    <footer className="w-full bg-white shadow-[0_-1px_8px_rgba(7,28,140,0.03)]">
      <div className="mx-auto w-full max-w-7xl px-4 pb-6 pt-10 lg:px-12">
        <div className="grid grid-cols-1 gap-10 pb-10 md:grid-cols-2 lg:grid-cols-5">
          <div className="flex flex-col gap-4 lg:col-span-2 lg:pr-6">
            <Logo className="h-9 self-start" />
            <p className="max-w-md text-sm leading-relaxed text-st-muted">
              An AI-based multi-modal platform that analyzes URLs, web page content, social media evidence and
              source code repositories to detect web threats and explain the evidence behind each result.
            </p>
            <div className="flex items-center gap-1.5 text-xs font-semibold text-st-muted">
              <ShieldCheck className="h-4 w-4 text-st-blue-dark" aria-hidden="true" />
              <span>Multi-modal, explainable threat analysis</span>
            </div>
          </div>

          {FOOTER_COLUMNS.map((column) => (
            <div key={column.title} className="flex flex-col gap-3">
              <span className="text-sm font-bold uppercase tracking-wider text-st-navy">{column.title}</span>
              <div className="flex flex-col gap-2">
                {column.links.map((link) => (
                  <Link key={link.label} to={link.to} className={linkClass}>{link.label}</Link>
                ))}
              </div>
            </div>
          ))}
        </div>

        <div className="flex flex-col items-center justify-between gap-4 border-t border-st-container pt-6 text-sm text-st-muted md:flex-row">
          <div className="flex flex-col items-center gap-1 text-center sm:flex-row sm:text-left">
            <span className="font-semibold text-st-ink">ScamTrace</span>
            <span>– AI-Based Multi-Modal Web Threat Detection and Security Intelligence System</span>
          </div>
          <div className="text-center text-xs font-semibold md:text-right">
            SLIIT Final Year Research Project – J26-SE-316 • © {new Date().getFullYear()}
          </div>
        </div>
      </div>
    </footer>
  )
}
