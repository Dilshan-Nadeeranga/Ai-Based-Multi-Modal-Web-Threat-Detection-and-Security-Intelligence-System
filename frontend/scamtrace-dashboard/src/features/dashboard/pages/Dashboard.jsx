import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { GitBranch, History as HistoryIcon, Images, ShieldAlert, UserCircle2 } from 'lucide-react'
import api from '../../../api/api.js'
import { useAuth } from '../../auth/hooks/useAuth.js'

const LINKS = [
  { to: '/url-analyzer', icon: ShieldAlert, title: 'Threat Analysis', text: 'Analyze a suspicious URL or domain.', tone: 'text-sky-400' },
  { to: '/social-visual-analysis', icon: Images, title: 'Social Visual Analysis', text: 'Analyze a social-media post: text, image, brand and linked webpage.', tone: 'text-violet-400' },
  { to: '/code-audit', icon: GitBranch, title: 'Repository Audit', text: 'Audit a public GitHub repository for vulnerabilities.', tone: 'text-emerald-400' },
  { to: '/history', icon: HistoryIcon, title: 'History', text: 'Your previous analyses and repository audits.', tone: 'text-amber-400' },
  { to: '/profile', icon: UserCircle2, title: 'Profile', text: 'Manage your account details and password.', tone: 'text-purple-400' },
]

export default function Dashboard() {
  const { user } = useAuth()
  const [counts, setCounts] = useState(null)

  useEffect(() => {
    let active = true
    Promise.all([api.get('/analysis/history'), api.get('/code-audit')])
      .then(([analyses, scans]) => {
        if (active) setCounts({ analyses: analyses.data.analyses.length, scans: scans.data.scans.length })
      })
      .catch(() => active && setCounts(null))
    return () => {
      active = false
    }
  }, [])

  return (
    <main className="flex-1 w-full max-w-6xl mx-auto px-4 py-10 text-slate-100 space-y-8">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Welcome, {user.name}</h1>
          <p className="text-sm text-slate-400">
            ScamTrace — AI-Based Multi-Modal Web Threat Detection and Security Intelligence System
          </p>
        </div>
        <Link to="/social-visual-analysis"
              className="flex items-center gap-2 rounded-lg bg-violet-600 hover:bg-violet-500 px-4 py-2 text-sm font-semibold text-white">
          <Images className="w-4 h-4" /> Social Visual Analysis
        </Link>
      </header>

      {counts && (
        <div className="grid grid-cols-2 gap-4 max-w-md">
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
            <p className="text-xs uppercase tracking-wide text-slate-400">My analyses</p>
            <p className="mt-1 text-2xl font-bold">{counts.analyses}</p>
          </div>
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
            <p className="text-xs uppercase tracking-wide text-slate-400">My repository audits</p>
            <p className="mt-1 text-2xl font-bold">{counts.scans}</p>
          </div>
        </div>
      )}

      <div className="grid sm:grid-cols-2 gap-4">
        {LINKS.map(({ to, icon: Icon, title, text, tone }) => (
          <Link key={to} to={to}
                className="group bg-slate-900/80 border border-slate-800 hover:border-sky-700 rounded-xl p-5 transition-colors">
            <Icon className={`w-6 h-6 ${tone}`} />
            <h2 className="mt-3 text-base font-semibold group-hover:text-sky-300">{title}</h2>
            <p className="mt-1 text-sm text-slate-400">{text}</p>
          </Link>
        ))}
      </div>
    </main>
  )
}
