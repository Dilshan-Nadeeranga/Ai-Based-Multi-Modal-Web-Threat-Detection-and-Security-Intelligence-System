import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { CircleAlert, Code, GitBranch, Layers, Plus, ScanSearch, Search, SearchX, ShieldAlert } from 'lucide-react'
import api, { getErrorMessage } from '../../../api/api.js'
import AppShell from '../../../components/AppShell.jsx'

const TABS = [
  { id: 'all', label: 'All Activity' },
  { id: 'analysis', label: 'Threat Analyses' },
  { id: 'audit', label: 'Repository Audits' },
]

const RISK_BADGES = {
  'High Risk Scam': 'bg-st-error-bg text-st-error-ink',
  'Medium Risk': 'bg-amber-100 text-amber-800',
  Suspicious: 'bg-st-fixed text-st-navy',
  'Low Risk': 'bg-st-container text-st-navy',
}

function formatDate(value) {
  return new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

function repoName(url = '') {
  return url.replace(/^https?:\/\/(www\.)?github\.com\//, '').replace(/\.git$/, '')
}

function toRecords(analyses, scans) {
  const fromAnalyses = analyses.map((item) => ({
    key: `a-${item.analysis_id}`,
    kind: 'analysis',
    id: item.analysis_id,
    target: item.input?.url || item.input?.repoUrl || item.input?.socialText || 'Text analysis',
    status: 'completed',
    risk: item.final_label,
    score: item.overall_score,
    date: item.created_at,
  }))
  const fromScans = scans.map((item) => ({
    key: `s-${item.scan_id}`,
    kind: 'audit',
    id: item.scan_id,
    target: repoName(item.repository_url),
    status: item.status,
    date: item.created_at,
    to: `/code-audit/report?scan=${encodeURIComponent(item.scan_id)}`,
  }))
  return [...fromAnalyses, ...fromScans].sort((a, b) => new Date(b.date) - new Date(a.date))
}

function SummaryCard({ icon: Icon, iconClass, value, label }) {
  return (
    <div className="flex items-center gap-4 rounded-xl bg-white p-5 shadow-sm ring-1 ring-st-container/60">
      <span className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-xl ${iconClass}`}>
        <Icon className="h-6 w-6" aria-hidden="true" />
      </span>
      <div>
        <p className="font-manrope text-3xl font-extrabold leading-none text-st-navy">{value}</p>
        <p className="mt-1 text-sm font-semibold text-st-muted">{label}</p>
      </div>
    </div>
  )
}

function EmptyState({ filtered }) {
  return (
    <div className="flex flex-col items-center justify-center px-4 py-14 text-center">
      <span className="mb-3 flex h-16 w-16 items-center justify-center rounded-2xl bg-st-container text-st-outline">
        <SearchX className="h-8 w-8" aria-hidden="true" />
      </span>
      <h3 className="font-manrope text-lg font-semibold text-st-navy">
        {filtered ? 'No matching records' : 'No history yet'}
      </h3>
      <p className="mt-1 max-w-sm text-sm text-st-muted">
        {filtered
          ? 'Try a different search term or filter.'
          : 'Your threat analyses and repository audits will appear here once you run them.'}
      </p>
      {!filtered && (
        <div className="mt-4 flex flex-wrap justify-center gap-2">
          <Link to="/url-analyzer" className="rounded-lg bg-st-navy-2 px-4 py-2 text-xs font-semibold text-white shadow-sm hover:bg-st-blue-dark">
            Analyze a URL
          </Link>
          <Link to="/code-audit" className="rounded-lg bg-st-container px-4 py-2 text-xs font-semibold text-st-navy hover:bg-st-high">
            Audit a Repository
          </Link>
        </div>
      )}
    </div>
  )
}

/** The gateway returns only the signed-in user's records. */
export default function History() {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [tab, setTab] = useState('all')
  const [search, setSearch] = useState('')

  useEffect(() => {
    let active = true
    Promise.all([api.get('/analysis/history'), api.get('/code-audit')])
      .then(([analyses, scans]) => active && setData({ analyses: analyses.data.analyses, scans: scans.data.scans }))
      .catch((err) => active && setError(getErrorMessage(err, 'Unable to load your history.')))
    return () => {
      active = false
    }
  }, [])

  const records = data ? toRecords(data.analyses, data.scans) : []
  const term = search.trim().toLowerCase()
  const visible = records.filter(
    (record) =>
      (tab === 'all' || record.kind === tab) &&
      (!term || [record.target, record.id, record.risk, record.status].some((value) => String(value ?? '').toLowerCase().includes(term)))
  )
  const highRisk = data ? data.analyses.filter((item) => item.final_label === 'High Risk Scam').length : 0
  const counts = { all: records.length, analysis: data?.analyses.length ?? 0, audit: data?.scans.length ?? 0 }

  return (
    <AppShell title="History">
      <div className="flex w-full flex-col gap-8 px-4 py-8 md:px-8">
        <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-center">
          <div className="flex flex-col gap-1">
            <span className="w-fit rounded-full bg-st-container px-2 py-0.5 text-[0.6875rem] font-bold uppercase tracking-widest text-st-blue-dark">
              Activity Log
            </span>
            <h1 className="font-manrope text-[1.75rem] font-bold tracking-tight text-st-navy lg:text-4xl">History</h1>
            <p className="max-w-2xl text-base text-st-muted">Review your previous threat analyses and repository audits.</p>
          </div>
          <Link
            to="/url-analyzer"
            className="flex w-fit items-center gap-1.5 rounded-lg bg-st-blue px-5 py-2 text-sm font-semibold text-white shadow-md transition hover:bg-st-blue-dark"
          >
            <Plus className="h-5 w-5" aria-hidden="true" /> New Analysis
          </Link>
        </div>

        {error && (
          <div role="alert" className="flex items-start gap-2 rounded-lg bg-st-error-bg p-3 text-sm text-st-error-ink">
            <CircleAlert className="mt-0.5 h-[18px] w-[18px] shrink-0" aria-hidden="true" /> {error}
          </div>
        )}

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <SummaryCard icon={Layers} iconClass="bg-st-blue/15 text-st-blue" value={data ? counts.all : '–'} label="Total Records" />
          <SummaryCard icon={ScanSearch} iconClass="bg-st-fixed text-st-blue-dark" value={data ? counts.analysis : '–'} label="Threat Analyses" />
          <SummaryCard icon={GitBranch} iconClass="bg-st-highest text-st-navy-2" value={data ? counts.audit : '–'} label="Repository Audits" />
          <SummaryCard icon={ShieldAlert} iconClass="bg-st-error-bg text-st-error" value={data ? highRisk : '–'} label="High-Risk Results" />
        </div>

        <section className="rounded-xl bg-white p-6 shadow-sm ring-1 ring-st-container/60">
          <div className="mb-5 flex flex-col justify-between gap-3 lg:flex-row lg:items-center">
            <div className="flex flex-wrap gap-1 rounded-lg bg-st-low p-1" role="tablist" aria-label="Filter history">
              {TABS.map(({ id, label }) => (
                <button
                  key={id}
                  type="button"
                  role="tab"
                  aria-selected={tab === id}
                  onClick={() => setTab(id)}
                  className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition ${
                    tab === id ? 'bg-st-navy-2 text-white shadow-sm' : 'text-st-muted hover:bg-st-container hover:text-st-navy'
                  }`}
                >
                  {label}
                  <span className={`rounded-full px-1.5 text-[0.625rem] font-bold ${tab === id ? 'bg-white/20' : 'bg-st-container'}`}>
                    {counts[id]}
                  </span>
                </button>
              ))}
            </div>
            <div className="relative w-full lg:w-80">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-st-outline" aria-hidden="true" />
              <input
                type="search"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search by target, ID or risk…"
                aria-label="Search history"
                className="w-full rounded-lg bg-st-low/60 py-2 pl-9 pr-3 text-sm text-st-navy outline-none ring-1 ring-st-container transition placeholder:text-st-outline focus:bg-white focus:ring-2 focus:ring-st-blue-dark"
              />
            </div>
          </div>

          {!data && !error && <p className="py-10 text-center text-sm text-st-muted">Loading history…</p>}

          {data && (visible.length ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead>
                  <tr className="bg-st-low/60 text-[0.6875rem] font-bold uppercase tracking-wider text-st-outline">
                    <th className="rounded-l-lg px-3 py-2">Type</th>
                    <th className="px-3 py-2">Target</th>
                    <th className="px-3 py-2">Record ID</th>
                    <th className="px-3 py-2">Status</th>
                    <th className="px-3 py-2">Result</th>
                    <th className="px-3 py-2">Date</th>
                    <th className="rounded-r-lg px-3 py-2 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-st-container">
                  {visible.map((record) => (
                    <tr key={record.key} className="transition-colors hover:bg-st-low">
                      <td className="whitespace-nowrap px-3 py-3">
                        <span className="flex items-center gap-1.5 text-xs font-semibold text-st-navy">
                          {record.kind === 'audit'
                            ? <Code className="h-4 w-4 text-st-blue-dark" aria-hidden="true" />
                            : <ScanSearch className="h-4 w-4 text-st-navy-2" aria-hidden="true" />}
                          {record.kind === 'audit' ? 'Repo Audit' : 'Threat Analysis'}
                        </span>
                      </td>
                      <td className="px-3 py-3">
                        <span className="block max-w-[260px] truncate font-mono text-xs text-st-ink" title={record.target}>{record.target}</span>
                      </td>
                      <td className="px-3 py-3">
                        <span className="block max-w-[180px] truncate font-mono text-[0.6875rem] text-st-outline" title={record.id}>{record.id}</span>
                      </td>
                      <td className="whitespace-nowrap px-3 py-3">
                        <span className="inline-flex items-center gap-1 rounded-full bg-st-container px-2 py-0.5 text-[0.6875rem] font-bold capitalize text-st-navy">
                          <span className="h-1.5 w-1.5 rounded-full bg-st-blue" />
                          {String(record.status || 'unknown').replace(/_/g, ' ')}
                        </span>
                      </td>
                      <td className="whitespace-nowrap px-3 py-3">
                        {record.risk ? (
                          <span className="flex items-center gap-2">
                            <span className={`rounded-full px-2 py-0.5 text-[0.6875rem] font-bold ${RISK_BADGES[record.risk] || 'bg-st-container text-st-navy'}`}>
                              {record.risk}
                            </span>
                            <span className="text-[0.6875rem] font-bold text-st-muted">{record.score}/100</span>
                          </span>
                        ) : (
                          <span className="text-xs text-st-outline">See report</span>
                        )}
                      </td>
                      <td className="whitespace-nowrap px-3 py-3 text-[0.6875rem] font-semibold text-st-outline">{formatDate(record.date)}</td>
                      <td className="whitespace-nowrap px-3 py-3 text-right">
                        {record.to ? (
                          <Link
                            to={record.to}
                            className="rounded-md bg-st-container px-2.5 py-1 text-[0.6875rem] font-bold text-st-navy shadow-sm transition hover:bg-st-navy-2 hover:text-white"
                          >
                            View Report
                          </Link>
                        ) : (
                          <span className="text-[0.6875rem] text-st-outline">—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState filtered={records.length > 0} />
          ))}

          {data && records.length > 0 && (
            <p className="mt-4 text-[0.6875rem] font-semibold text-st-outline">
              Showing {visible.length} of {records.length} records. The gateway keeps your latest 200 of each type.
            </p>
          )}
        </section>
      </div>
    </AppShell>
  )
}
