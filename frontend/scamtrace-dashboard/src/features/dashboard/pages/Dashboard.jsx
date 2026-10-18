import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Activity,
  ArrowRight,
  CircleAlert,
  ClipboardCheck,
  Code,
  Cpu,
  GitBranch,
  History as HistoryIcon,
  Images,
  Link as LinkIcon,
  Network,
  Plus,
  ScanSearch,
  SearchX,
  ShieldCheck,
  Terminal,
} from 'lucide-react'
import api, { getErrorMessage } from '../../../api/api.js'
import AppShell from '../../../components/AppShell.jsx'
import { useAuth } from '../../auth/hooks/useAuth.js'
import { SERVICES, checkGateway, checkServices } from '../serviceHealth.js'

const RECENT_LIMIT = 6

const WORKFLOWS = [
  {
    to: '/url-analyzer',
    icon: LinkIcon,
    iconClass: 'bg-st-navy-2 text-white',
    engine: 'C1 & C2',
    title: 'Threat Analysis',
    text: 'Analyze a suspicious URL or domain using URL and domain intelligence together with web page content and behavior analysis.',
    tags: ['URL & Domain', 'HTML Content', 'Script Behavior'],
    action: 'Analyze URL',
  },
  {
    to: '/social-visual-analysis',
    icon: Images,
    iconClass: 'bg-st-blue text-white',
    engine: 'C3',
    title: 'Social Visual Analysis',
    text: 'Analyze social media text, screenshots, logos and linked web pages to detect brand impersonation and visual scams.',
    tags: ['OCR', 'Logo & Brand', 'Visual Similarity'],
    action: 'Analyze Social Content',
  },
  {
    to: '/code-audit',
    icon: Terminal,
    iconClass: 'bg-[#242e57] text-white',
    engine: 'C4',
    title: 'Repository Audit',
    text: 'Audit a public GitHub repository for security vulnerabilities and code quality issues, with AI-assisted remediation suggestions.',
    tags: ['Static Analysis', 'AST Metrics', 'AI Remediation'],
    action: 'Audit Repository',
  },
]

const COMPONENTS = [
  { id: 'c1', title: 'C1: URL & Domain Analyzer', text: 'Lexical URL features, domain age, DNS and hosting signals.', to: '/url-analyzer' },
  { id: 'c2', title: 'C2: HTML Content & Behavior', text: 'DOM structure, multilingual page text (English, Sinhala, Tamil) and static JavaScript analysis.' },
  { id: 'c3', title: 'C3: Social & Visual Analyzer', text: 'OCR, web page capture, logo detection and brand comparison.', to: '/social-visual-analysis' },
  { id: 'c4', title: 'C4: Code Vulnerability Auditor', text: 'Semgrep and AST-based scanning, risk scoring and AI-assisted patches.', to: '/code-audit' },
]

const RISK_LEVELS = [
  { label: 'High Risk Scam', short: 'High', color: '#ba1a1a', dot: 'bg-st-error', badge: 'bg-st-error-bg text-st-error-ink' },
  { label: 'Medium Risk', short: 'Medium', color: '#d97706', dot: 'bg-amber-600', badge: 'bg-amber-100 text-amber-800' },
  { label: 'Suspicious', short: 'Suspicious', color: '#0074dd', dot: 'bg-st-blue', badge: 'bg-st-fixed text-st-navy' },
  { label: 'Low Risk', short: 'Low', color: '#071c8c', dot: 'bg-st-navy-2', badge: 'bg-st-container text-st-navy' },
]

const STATUS_STYLES = {
  online: { text: 'Online', className: 'text-st-blue-dark', dot: 'bg-st-blue' },
  offline: { text: 'Offline', className: 'text-st-error', dot: 'bg-st-error' },
  unknown: { text: 'Unknown', className: 'text-st-outline', dot: 'bg-st-outline' },
  checking: { text: 'Checking…', className: 'text-st-outline', dot: 'bg-st-outline animate-pulse' },
}

function formatDate(value) {
  return new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

function repoName(url = '') {
  return url.replace(/^https?:\/\/(www\.)?github\.com\//, '').replace(/\.git$/, '')
}

function toActivity(analyses, scans) {
  const fromAnalyses = analyses.map((item) => ({
    key: `a-${item.analysis_id}`,
    kind: 'analysis',
    target: item.input?.url || item.input?.repoUrl || item.input?.socialText || 'Text analysis',
    status: 'completed',
    risk: item.final_label,
    score: item.overall_score,
    date: item.created_at,
    to: '/history',
    action: 'View History',
  }))
  const fromScans = scans.map((item) => ({
    key: `s-${item.scan_id}`,
    kind: 'audit',
    target: repoName(item.repository_url),
    status: item.status,
    risk: null,
    date: item.created_at,
    to: `/code-audit/scans/${encodeURIComponent(item.scan_id)}`,
    action: 'View Report',
  }))
  return [...fromAnalyses, ...fromScans].sort((a, b) => new Date(b.date) - new Date(a.date))
}

function Card({ className = '', children }) {
  return <div className={`rounded-xl bg-white p-6 shadow-sm ring-1 ring-st-container/60 ${className}`}>{children}</div>
}

function StatCard({ icon: Icon, iconClass, value, title, text, badge, badgeClass }) {
  return (
    <div className="group relative overflow-hidden rounded-xl bg-white p-6 shadow-sm ring-1 ring-st-container/60 transition-shadow hover:shadow-md">
      <div className="absolute -bottom-4 -right-4 h-24 w-24 rounded-full bg-st-low transition-transform group-hover:scale-125" />
      <div className="relative z-10 flex items-start justify-between gap-2">
        <span className={`flex h-12 w-12 items-center justify-center rounded-xl ${iconClass}`}>
          <Icon className="h-6 w-6" aria-hidden="true" />
        </span>
        {badge && (
          <span className={`max-w-[60%] truncate rounded-full px-2 py-0.5 text-[0.6875rem] font-bold ${badgeClass}`}>{badge}</span>
        )}
      </div>
      <div className="relative z-10 mt-6">
        <p className="font-manrope text-5xl font-extrabold leading-none tracking-tight text-st-navy">{value}</p>
        <p className="mt-2 font-manrope text-lg font-semibold text-st-ink">{title}</p>
        <p className="mt-0.5 text-sm text-st-outline">{text}</p>
      </div>
    </div>
  )
}

function StatusPill({ status }) {
  const style = STATUS_STYLES[status] || STATUS_STYLES.unknown
  return (
    <span className={`flex items-center gap-1.5 font-mono text-xs font-semibold ${style.className}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${style.dot}`} />
      {style.text}
    </span>
  )
}

function RiskBadge({ label }) {
  if (!label) return <span className="text-xs text-st-outline">See report</span>
  const level = RISK_LEVELS.find((item) => item.label === label)
  return (
    <span className={`whitespace-nowrap rounded-full px-2 py-0.5 text-[0.6875rem] font-bold ${level?.badge || 'bg-st-container text-st-navy'}`}>
      {label}
    </span>
  )
}

function RecentActivity({ items }) {
  return (
    <Card className="flex flex-col justify-between lg:col-span-7">
      <div>
        <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
          <h3 className="font-manrope text-xl font-semibold text-st-navy">Recent Activity</h3>
          <Link to="/history" className="flex items-center gap-0.5 text-xs font-semibold text-st-blue-dark hover:underline">
            View All <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
          </Link>
        </div>

        {items.length ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="bg-st-low/60 text-[0.6875rem] font-bold uppercase tracking-wider text-st-outline">
                  <th className="rounded-l-lg px-2 py-2">Type</th>
                  <th className="px-2 py-2">Target</th>
                  <th className="px-2 py-2">Status</th>
                  <th className="px-2 py-2">Risk</th>
                  <th className="px-2 py-2">Date</th>
                  <th className="rounded-r-lg px-2 py-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-st-container">
                {items.slice(0, RECENT_LIMIT).map((item) => (
                  <tr key={item.key} className="transition-colors hover:bg-st-low">
                    <td className="whitespace-nowrap px-2 py-2.5">
                      <span className="flex items-center gap-1.5 text-xs font-semibold text-st-navy">
                        {item.kind === 'audit'
                          ? <Code className="h-4 w-4 text-st-blue-dark" aria-hidden="true" />
                          : <ScanSearch className="h-4 w-4 text-st-navy-2" aria-hidden="true" />}
                        {item.kind === 'audit' ? 'Repo Audit' : 'Threat Analysis'}
                      </span>
                    </td>
                    <td className="px-2 py-2.5">
                      <span className="block max-w-[180px] truncate font-mono text-xs text-st-ink" title={item.target}>{item.target}</span>
                    </td>
                    <td className="whitespace-nowrap px-2 py-2.5">
                      <span className="inline-flex items-center gap-1 rounded-full bg-st-container px-2 py-0.5 text-[0.6875rem] font-bold capitalize text-st-navy">
                        <span className="h-1.5 w-1.5 rounded-full bg-st-blue" />
                        {String(item.status || 'unknown').replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-2 py-2.5"><RiskBadge label={item.risk} /></td>
                    <td className="whitespace-nowrap px-2 py-2.5 text-[0.6875rem] font-semibold text-st-outline">{formatDate(item.date)}</td>
                    <td className="whitespace-nowrap px-2 py-2.5 text-right">
                      <Link
                        to={item.to}
                        className="rounded-md bg-st-container px-2.5 py-1 text-[0.6875rem] font-bold text-st-navy shadow-sm transition hover:bg-st-navy-2 hover:text-white"
                      >
                        {item.action}
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center px-4 py-10 text-center">
            <span className="mb-3 flex h-16 w-16 items-center justify-center rounded-2xl bg-st-container text-st-outline">
              <SearchX className="h-8 w-8" aria-hidden="true" />
            </span>
            <h4 className="font-manrope text-lg font-semibold text-st-navy">No recent analyses yet</h4>
            <p className="mt-1 max-w-sm text-sm text-st-muted">
              Submit a suspicious URL or run a repository audit to see your results here.
            </p>
            <Link
              to="/url-analyzer"
              className="mt-4 rounded-lg bg-st-navy-2 px-4 py-2 text-xs font-semibold text-white shadow-sm hover:bg-st-blue-dark"
            >
              Start Your First Analysis
            </Link>
          </div>
        )}
      </div>
      <p className="mt-4 pt-2 text-[0.6875rem] font-semibold text-st-outline">
        Showing your latest {Math.min(items.length, RECENT_LIMIT)} of {items.length} records.
      </p>
    </Card>
  )
}

function RiskDistribution({ analyses }) {
  const total = analyses.length
  const counts = RISK_LEVELS.map((level) => analyses.filter((item) => item.final_label === level.label).length)
  const shares = counts.map((count) => (total ? (count / total) * 100 : 0))
  const segments = shares.map((share, index) => ({
    share,
    offset: shares.slice(0, index).reduce((sum, value) => sum + value, 0),
    color: RISK_LEVELS[index].color,
  }))

  return (
    <Card className="flex flex-1 flex-col justify-between">
      <div className="mb-2 flex items-center justify-between">
        <h3 className="font-manrope text-xl font-semibold text-st-navy">Risk Distribution</h3>
        <span className="text-[0.6875rem] font-bold uppercase tracking-wider text-st-outline">Threat Analyses</span>
      </div>
      <div className="my-2 flex items-center justify-around gap-4">
        <div className="relative flex h-28 w-28 items-center justify-center">
          <svg className="h-full w-full -rotate-90" viewBox="0 0 36 36" aria-hidden="true">
            <circle cx="18" cy="18" r="15.9155" fill="none" stroke="#ececff" strokeWidth="3.5" />
            {segments.map((segment, index) =>
              segment.share > 0 ? (
                <circle
                  key={RISK_LEVELS[index].label}
                  cx="18"
                  cy="18"
                  r="15.9155"
                  fill="none"
                  stroke={segment.color}
                  strokeWidth="3.5"
                  strokeDasharray={`${segment.share} ${100 - segment.share}`}
                  strokeDashoffset={-segment.offset}
                />
              ) : null
            )}
          </svg>
          <div className="absolute flex flex-col items-center leading-none">
            <span className="font-manrope text-2xl font-bold text-st-navy">{total}</span>
            <span className="mt-0.5 text-[0.6875rem] font-bold uppercase text-st-outline">{total === 1 ? 'Analysis' : 'Analyses'}</span>
          </div>
        </div>
        <ul className="flex flex-col gap-1.5 text-xs font-semibold">
          {RISK_LEVELS.map((level, index) => (
            <li key={level.label} className="flex items-center justify-between gap-4">
              <span className="flex items-center gap-1.5 text-st-muted">
                <span className={`h-2.5 w-2.5 rounded-full ${level.dot}`} /> {level.short}
              </span>
              <span className="font-bold text-st-navy">
                {counts[index]}
                {total > 0 && counts[index] > 0 && ` (${Math.round((counts[index] / total) * 100)}%)`}
              </span>
            </li>
          ))}
        </ul>
      </div>
      <p className="mt-1 text-center text-sm text-st-outline">
        {total ? `Based on the final label of your ${total} saved threat ${total === 1 ? 'analysis' : 'analyses'}.` : 'No scored threat analyses yet.'}
      </p>
    </Card>
  )
}

function WorkloadBreakdown({ analyses, scans }) {
  const total = analyses + scans
  const rows = [
    { label: 'Threat Analyses (C1–C4 via Gateway)', count: analyses, bar: 'bg-st-blue' },
    { label: 'Repository Audits (C4)', count: scans, bar: 'bg-st-navy-2' },
  ]
  return (
    <Card className="flex flex-1 flex-col justify-between">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="font-manrope text-xl font-semibold text-st-navy">Workload Breakdown</h3>
        <span className="text-[0.6875rem] font-semibold text-st-blue-dark">{total} Total</span>
      </div>
      <div className="flex flex-col gap-3">
        {rows.map((row) => {
          const share = total ? Math.round((row.count / total) * 100) : 0
          return (
            <div key={row.label} className="flex flex-col gap-1">
              <div className="flex justify-between text-[0.6875rem] font-bold">
                <span className="text-st-ink">{row.label}</span>
                <span className={row.count ? 'text-st-navy' : 'text-st-outline'}>{share}% ({row.count})</span>
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-st-container">
                <div className={`h-full rounded-full ${row.bar}`} style={{ width: `${share}%` }} />
              </div>
            </div>
          )
        })}
      </div>
      <p className="mt-3 text-[0.6875rem] text-st-outline">Social visual analyses run directly on C3 and are not counted here.</p>
    </Card>
  )
}

function SystemStatus({ health }) {
  const rows = [
    { label: 'API Gateway', status: health?.gateway ?? 'checking' },
    { label: 'Database', status: health?.database ?? 'checking' },
    ...SERVICES.map((service) => ({ label: service.label, status: health?.services?.[service.id] ?? 'checking' })),
  ]
  const allOnline = health?.services && rows.every((row) => row.status === 'online')

  return (
    <Card className="flex flex-col justify-between lg:col-span-5">
      <div>
        <div className="mb-4 flex items-center justify-between">
          <h3 className="flex items-center gap-2 font-manrope text-xl font-semibold text-st-navy">
            <Network className="h-5 w-5 text-st-blue" aria-hidden="true" /> System Status
          </h3>
          {health?.services && (
            <span className={`flex items-center gap-1 rounded-full px-2 py-0.5 text-[0.6875rem] font-bold ${allOnline ? 'bg-st-container text-st-blue-dark' : 'bg-amber-100 text-amber-800'}`}>
              <span className={`h-1.5 w-1.5 rounded-full ${allOnline ? 'bg-st-blue' : 'bg-amber-600'}`} />
              {allOnline ? 'All Online' : 'Partially Online'}
            </span>
          )}
        </div>
        <ul className="flex flex-col gap-2 text-xs font-semibold">
          {rows.map((row) => (
            <li key={row.label} className="flex items-center justify-between gap-2 rounded-md bg-st-low px-3 py-2">
              <span className="text-st-ink">{row.label}</span>
              <StatusPill status={row.status} />
            </li>
          ))}
        </ul>
      </div>
      <div className="mt-6 flex items-center gap-2 rounded-lg bg-st-low p-2.5">
        <span className="flex h-7 w-7 items-center justify-center rounded bg-st-navy-2 text-[0.625rem] font-bold text-white">SL</span>
        <div className="leading-tight">
          <p className="text-[0.6875rem] font-bold text-st-navy">SLIIT Final Year Research Project</p>
          <p className="text-[0.6875rem] text-st-outline">Project ID: J26-SE-316</p>
        </div>
      </div>
    </Card>
  )
}

export default function Dashboard() {
  const { user } = useAuth()
  const [data, setData] = useState(null)
  const [error, setError] = useState('')
  const [health, setHealth] = useState(null)

  useEffect(() => {
    let active = true
    Promise.all([api.get('/analysis/history'), api.get('/code-audit')])
      .then(([analyses, scans]) => {
        if (active) setData({ analyses: analyses.data.analyses, scans: scans.data.scans })
      })
      .catch((err) => active && setError(getErrorMessage(err, 'Unable to load your activity.')))
    Promise.all([checkGateway(), checkServices()]).then(([gateway, services]) => {
      if (active) setHealth({ ...gateway, services })
    })
    return () => {
      active = false
    }
  }, [])

  const analyses = data?.analyses ?? []
  const scans = data?.scans ?? []
  const activity = toActivity(analyses, scans)
  const highRisk = analyses.filter((item) => item.final_label === 'High Risk Scam').length
  const firstName = user.name.trim().split(/\s+/)[0]
  const loadingValue = data ? null : '–'

  return (
    <AppShell title="Dashboard">
      <div className="flex w-full flex-col gap-10 px-4 py-8 md:px-8">
        <div className="flex flex-col justify-between gap-4 lg:flex-row lg:items-center">
          <div className="flex flex-col gap-1">
            <span className="w-fit rounded-full bg-st-container px-2 py-0.5 text-[0.6875rem] font-bold uppercase tracking-widest text-st-blue-dark">
              {user.role === 'ADMIN' ? 'Admin Workspace' : 'My Workspace'}
            </span>
            <h1 className="font-manrope text-[1.75rem] font-bold tracking-tight text-st-navy lg:text-4xl">Welcome back, {firstName}</h1>
            <p className="max-w-2xl text-base text-st-muted">
              Monitor your threat analyses, repository audits and recent ScamTrace activity.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Link
              to="/history"
              className="flex items-center gap-1.5 rounded-lg bg-white px-4 py-2 text-sm font-semibold text-st-navy shadow-sm ring-1 ring-st-container transition hover:bg-st-container"
            >
              <HistoryIcon className="h-[18px] w-[18px] text-st-blue-dark" aria-hidden="true" /> View History
            </Link>
            <Link
              to="/url-analyzer"
              className="flex items-center gap-1.5 rounded-lg bg-st-blue px-5 py-2 text-sm font-semibold text-white shadow-md transition hover:bg-st-blue-dark"
            >
              <Plus className="h-5 w-5" aria-hidden="true" /> New Analysis
            </Link>
          </div>
        </div>

        {error && (
          <div role="alert" className="flex items-start gap-2 rounded-lg bg-st-error-bg p-3 text-sm text-st-error-ink">
            <CircleAlert className="mt-0.5 h-[18px] w-[18px] shrink-0" aria-hidden="true" /> {error}
          </div>
        )}

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard
            icon={ScanSearch}
            iconClass="bg-st-fixed text-st-blue-dark"
            value={loadingValue ?? analyses.length}
            title="My Analyses"
            text="Threat analyses submitted"
            badge={analyses[0] ? `Score ${analyses[0].overall_score}/100` : 'None yet'}
            badgeClass="bg-st-high text-st-muted"
          />
          <StatCard
            icon={GitBranch}
            iconClass="bg-st-highest text-st-navy-2"
            value={loadingValue ?? scans.length}
            title="Repository Audits"
            text="Repositories audited"
            badge={scans[0] ? `Latest: ${repoName(scans[0].repository_url).split('/').pop()}` : 'None yet'}
            badgeClass="bg-st-fixed text-st-navy"
          />
          <StatCard
            icon={ShieldCheck}
            iconClass="bg-st-high text-st-blue-dark"
            value={loadingValue ?? highRisk}
            title="High-Risk Results"
            text="Analyses labelled High Risk Scam"
            badge={data ? (highRisk ? 'Needs review' : 'Clean') : null}
            badgeClass={highRisk ? 'bg-st-error-bg text-st-error-ink' : 'bg-st-high text-st-blue-dark'}
          />
          <StatCard
            icon={ClipboardCheck}
            iconClass="bg-st-blue/15 text-st-blue"
            value={loadingValue ?? activity.length}
            title="Total Activity"
            text="Analyses and audits combined"
            badge={activity[0] ? `Last: ${new Date(activity[0].date).toLocaleDateString()}` : 'No activity yet'}
            badgeClass="bg-st-container text-st-muted"
          />
        </div>

        <section className="flex flex-col gap-4">
          <div className="flex flex-wrap items-end justify-between gap-2">
            <div>
              <span className="block text-[0.6875rem] font-bold uppercase tracking-wider text-st-outline">Detection Workflows</span>
              <h2 className="font-manrope text-2xl font-bold text-st-navy">Start an Analysis</h2>
            </div>
            <span className="text-xs font-semibold text-st-muted">Choose an analysis component</span>
          </div>
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            {WORKFLOWS.map(({ to, icon: Icon, iconClass, engine, title, text, tags, action }) => (
              <Link
                key={to}
                to={to}
                className="group flex flex-col justify-between rounded-xl bg-white p-6 shadow-sm ring-1 ring-st-container/60 transition-all hover:shadow-lg"
              >
                <div className="flex flex-col gap-4">
                  <div className="flex items-center justify-between">
                    <span className={`flex h-12 w-12 items-center justify-center rounded-xl shadow-sm ${iconClass}`}>
                      <Icon className="h-6 w-6" aria-hidden="true" />
                    </span>
                    <span className="text-[0.6875rem] font-bold uppercase tracking-wider text-st-outline">Component {engine}</span>
                  </div>
                  <div>
                    <h3 className="font-manrope text-xl font-semibold text-st-navy transition-colors group-hover:text-st-blue">{title}</h3>
                    <p className="mt-1 text-sm text-st-muted">{text}</p>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {tags.map((tag) => (
                      <span key={tag} className="rounded-full bg-st-low px-2 py-0.5 text-[0.6875rem] font-bold text-st-muted">{tag}</span>
                    ))}
                  </div>
                </div>
                <span className="mt-6 flex w-full items-center justify-between rounded-lg bg-st-low px-4 py-2 text-sm font-semibold text-st-navy transition-all group-hover:bg-st-navy-2 group-hover:text-white">
                  {action} <ArrowRight className="h-[18px] w-[18px]" aria-hidden="true" />
                </span>
              </Link>
            ))}
          </div>
        </section>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          <RecentActivity items={activity} />
          <div className="flex flex-col gap-4 lg:col-span-5">
            <RiskDistribution analyses={analyses} />
            <WorkloadBreakdown analyses={analyses.length} scans={scans.length} />
          </div>
        </div>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          <Card className="flex flex-col justify-between lg:col-span-7">
            <div>
              <div className="mb-4 flex items-center justify-between">
                <h3 className="flex items-center gap-2 font-manrope text-xl font-semibold text-st-navy">
                  <Cpu className="h-5 w-5 text-st-blue-dark" aria-hidden="true" /> ScamTrace Analysis Components
                </h3>
              </div>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                {COMPONENTS.map((component) => (
                  <div key={component.id} className="flex flex-col justify-between rounded-lg bg-st-low p-4 transition-colors hover:bg-st-container">
                    <div>
                      <div className="mb-1 flex items-start justify-between gap-2">
                        <span className="text-xs font-bold text-st-navy">{component.title}</span>
                        <StatusPill status={health?.services?.[component.id] ?? 'checking'} />
                      </div>
                      <p className="text-sm text-st-muted">{component.text}</p>
                    </div>
                    {component.to ? (
                      <Link to={component.to} className="mt-2 inline-flex items-center gap-1 text-[0.6875rem] font-bold text-st-blue-dark hover:underline">
                        Open <ArrowRight className="h-3 w-3" aria-hidden="true" />
                      </Link>
                    ) : (
                      <span className="mt-2 text-[0.6875rem] font-bold text-st-outline">Used inside Threat Analysis</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
            <p className="mt-4 flex items-center gap-1.5 text-[0.6875rem] font-semibold text-st-outline">
              <Activity className="h-3.5 w-3.5" aria-hidden="true" /> Status is checked from your browser each time the dashboard loads.
            </p>
          </Card>
          <SystemStatus health={health} />
        </div>
      </div>
    </AppShell>
  )
}
