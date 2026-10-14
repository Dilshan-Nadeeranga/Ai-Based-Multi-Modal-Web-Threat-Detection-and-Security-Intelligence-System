import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Activity, GitBranch, LayoutDashboard, ShieldCheck, Users, UserX } from 'lucide-react'
import api, { getErrorMessage } from '../../../api/api.js'
import { FormAlert } from '../../auth/components/AuthLayout.jsx'

function Stat({ icon: Icon, label, value, tone = 'text-sky-400' }) {
  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5">
      <div className="flex items-center gap-2 text-xs uppercase tracking-wide text-slate-400">
        <Icon className={`w-4 h-4 ${tone}`} /> {label}
      </div>
      <p className="mt-2 text-3xl font-bold text-slate-100">{value ?? '—'}</p>
    </div>
  )
}

function RecentList({ title, items, empty, render }) {
  return (
    <section className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-3">
      <h2 className="text-base font-semibold">{title}</h2>
      {items?.length ? (
        <ul className="divide-y divide-slate-800 text-sm">{items.slice(0, 5).map(render)}</ul>
      ) : (
        <p className="text-sm text-slate-500">{empty}</p>
      )}
    </section>
  )
}

export default function AdminDashboard() {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    Promise.all([api.get('/admin/users'), api.get('/admin/analyses'), api.get('/admin/code-audits')])
      .then(([users, analyses, scans]) => {
        if (active) setData({ users: users.data.users, analyses: analyses.data.analyses, scans: scans.data.scans })
      })
      .catch((err) => active && setError(getErrorMessage(err, 'Unable to load admin data.')))
    return () => {
      active = false
    }
  }, [])

  const users = data?.users
  return (
    <main className="flex-1 w-full max-w-6xl mx-auto px-4 py-10 text-slate-100 space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <LayoutDashboard className="w-8 h-8 text-purple-400" />
          <div>
            <h1 className="text-2xl font-semibold">Admin Dashboard</h1>
            <p className="text-sm text-slate-400">Users, analyses and repository audits across ScamTrace.</p>
          </div>
        </div>
        <Link to="/admin/users"
              className="rounded-lg bg-sky-600 hover:bg-sky-500 px-4 py-2 text-sm font-semibold text-white">
          Manage users
        </Link>
      </header>

      <FormAlert>{error}</FormAlert>
      {!data && !error && <p className="text-sm text-slate-400">Loading…</p>}

      {data && (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
            <Stat icon={Users} label="Users" value={users.length} />
            <Stat icon={ShieldCheck} label="Admins" value={users.filter((u) => u.role === 'ADMIN').length} tone="text-purple-400" />
            <Stat icon={UserX} label="Disabled" value={users.filter((u) => !u.is_active).length} tone="text-red-400" />
            <Stat icon={Activity} label="Analyses" value={data.analyses.length} tone="text-amber-400" />
            <Stat icon={GitBranch} label="Repo audits" value={data.scans.length} tone="text-emerald-400" />
          </div>

          <div className="grid md:grid-cols-2 gap-4">
            <RecentList
              title="Recent analyses (all users)" items={data.analyses} empty="No analyses yet."
              render={(a) => (
                <li key={a.analysis_id} className="py-2 flex justify-between gap-3">
                  <span className="truncate">{a.input?.url || a.input?.repoUrl || 'Text analysis'}</span>
                  <span className="text-slate-400 whitespace-nowrap">{a.owner_email}</span>
                </li>
              )}
            />
            <RecentList
              title="Recent repository audits (all users)" items={data.scans} empty="No repository audits yet."
              render={(s) => (
                <li key={s.scan_id} className="py-2 flex justify-between gap-3">
                  <Link to={`/code-audit/report?scan=${encodeURIComponent(s.scan_id)}`}
                        className="truncate text-sky-400 hover:text-sky-300">
                    {s.repository_url.replace('https://github.com/', '')}
                  </Link>
                  <span className="text-slate-400 whitespace-nowrap">{s.owner_email}</span>
                </li>
              )}
            />
          </div>

          <p className="text-xs text-slate-500">System settings will be managed here in a later sprint.</p>
        </>
      )}
    </main>
  )
}
