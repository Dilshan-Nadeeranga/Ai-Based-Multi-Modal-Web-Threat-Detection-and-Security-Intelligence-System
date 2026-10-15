import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { History as HistoryIcon } from 'lucide-react'
import api, { getErrorMessage } from '../../../api/api.js'
import { FormAlert } from '../../auth/components/AuthLayout.jsx'

function formatDate(value) {
  return new Date(value).toLocaleString()
}

/** The gateway returns only the signed-in user's records. */
export default function History() {
  const [data, setData] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let active = true
    Promise.all([api.get('/analysis/history'), api.get('/code-audit')])
      .then(([analyses, scans]) => active && setData({ analyses: analyses.data.analyses, scans: scans.data.scans }))
      .catch((err) => active && setError(getErrorMessage(err, 'Unable to load your history.')))
    return () => {
      active = false
    }
  }, [])

  return (
    <main className="flex-1 w-full max-w-5xl mx-auto px-4 py-10 text-slate-100 space-y-6">
      <header className="flex items-center gap-3">
        <HistoryIcon className="w-8 h-8 text-amber-400" />
        <div>
          <h1 className="text-2xl font-semibold">History</h1>
          <p className="text-sm text-slate-400">Your analyses and repository audits.</p>
        </div>
      </header>

      <FormAlert>{error}</FormAlert>
      {!data && !error && <p className="text-sm text-slate-400">Loading history…</p>}

      {data && (
        <>
          <section className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-3">
            <h2 className="text-base font-semibold">Repository audits</h2>
            {data.scans.length ? (
              <ul className="divide-y divide-slate-800 text-sm">
                {data.scans.map((scan) => (
                  <li key={scan.scan_id} className="py-2.5 flex flex-wrap justify-between gap-2">
                    <Link to={`/code-audit/report?scan=${encodeURIComponent(scan.scan_id)}`}
                          className="text-sky-400 hover:text-sky-300 break-all">
                      {scan.repository_url.replace('https://github.com/', '')}
                    </Link>
                    <span className="text-slate-400">{scan.scan_id} · {formatDate(scan.created_at)}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-slate-500">
                No repository audits yet. <Link to="/code-audit" className="text-sky-400">Audit a repository</Link>.
              </p>
            )}
          </section>

          <section className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-3">
            <h2 className="text-base font-semibold">Multi-component analyses</h2>
            {data.analyses.length ? (
              <ul className="divide-y divide-slate-800 text-sm">
                {data.analyses.map((analysis) => (
                  <li key={analysis.analysis_id} className="py-2.5 flex flex-wrap justify-between gap-2">
                    <span className="break-all">{analysis.input?.url || analysis.input?.repoUrl || 'Text analysis'}</span>
                    <span className="text-slate-400">
                      {analysis.final_label} ({analysis.overall_score}/100) · {formatDate(analysis.created_at)}
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-slate-500">No analyses yet.</p>
            )}
          </section>
        </>
      )}
    </main>
  )
}
