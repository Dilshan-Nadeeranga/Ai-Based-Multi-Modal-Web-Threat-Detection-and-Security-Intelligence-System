import { useNavigate } from 'react-router-dom'
import { ChevronRight } from 'lucide-react'
import { defangHost, defangUrl } from '../api/defang.js'
import { CLASSES, CLASS_LABELS, LANGUAGE_LABELS, SOURCE_LABELS, formatTime } from '../constants.js'
import VerdictBadge from './VerdictBadge.jsx'
import { CopyButton, SelectField } from './ui.jsx'

const shortTime = (iso) =>
  new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })

/** Scan rows (feed + history). URLs are defanged text with a copy button; "View" opens the result. */
export default function ScanTable({ items, highlightIds, compact = false }) {
  const navigate = useNavigate()
  return (
    <div className="overflow-x-auto">
      <table className={`w-full ${compact ? "min-w-[680px]" : "min-w-[820px]"} border-separate border-spacing-0 text-sm`}>
        <thead>
          <tr className="text-left font-mono text-[0.6875rem] uppercase tracking-wider text-slate-400">
            <th scope="col" className="border-b border-slate-800 px-2 py-2 font-medium">Time</th>
            <th scope="col" className="border-b border-slate-800 px-2 py-2 font-medium">Verdict</th>
            <th scope="col" className="border-b border-slate-800 px-2 py-2 text-right font-medium">Risk</th>
            <th scope="col" className="border-b border-slate-800 px-2 py-2 font-medium">Class</th>
            <th scope="col" className="border-b border-slate-800 px-2 py-2 font-medium">URL (defanged)</th>
            {!compact && <th scope="col" className="border-b border-slate-800 px-2 py-2 font-medium">Lang</th>}
            <th scope="col" className="border-b border-slate-800 px-2 py-2 font-medium">Source</th>
            <th scope="col" className="border-b border-slate-800 px-2 py-2"><span className="sr-only">Open</span></th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => {
            const url = defangUrl(item.url)
            return (
              <tr
                key={item.id}
                onClick={() => navigate(`/c2/scans/${item.id}`)}
                className={`cursor-pointer align-middle hover:bg-slate-800/50 ${highlightIds?.has(item.id) ? 'c2-enter bg-cyan-400/5' : ''}`}
              >
                <td className="whitespace-nowrap border-b border-slate-800/70 px-2 py-2 font-mono text-xs text-slate-400" title={formatTime(item.created_at)}>
                  {compact ? new Date(item.created_at).toLocaleTimeString() : shortTime(item.created_at)}
                </td>
                <td className="border-b border-slate-800/70 px-2 py-2">
                  <VerdictBadge verdict={item.verdict} label={item.verdict ? null : item.status} />
                </td>
                <td className="border-b border-slate-800/70 px-2 py-2 text-right font-mono text-slate-100">{item.risk_score ?? '—'}</td>
                <td className="border-b border-slate-800/70 px-2 py-2 text-slate-200">
                  {item.verdict === 'Legitimate' ? '—' : CLASS_LABELS[item.threat_class] || item.threat_class || '—'}
                </td>
                <td className={`${"max-w-[17rem]"} border-b border-slate-800/70 px-2 py-2`}>
                  <span className="flex items-center gap-2" onClick={(event) => event.stopPropagation()}>
                    <span className="truncate font-mono text-xs text-cyan-100" title={url}>{url}</span>
                    <CopyButton value={url} />
                  </span>
                  {item.final_domain && !compact && (
                    <span className="block truncate font-mono text-[0.6875rem] text-slate-500">{defangHost(item.final_domain)}</span>
                  )}
                </td>
                {!compact && <td className="border-b border-slate-800/70 px-2 py-2 font-mono text-xs text-slate-300">{LANGUAGE_LABELS[item.language] || item.language || '—'}</td>}
                <td className="whitespace-nowrap border-b border-slate-800/70 px-2 py-2 text-xs text-slate-300">
                  {SOURCE_LABELS[item.source] || item.source}
                  {item.demo && <span className="ml-1 font-mono text-amber-300">demo</span>}
                </td>
                <td className="border-b border-slate-800/70 px-2 py-2 text-right">
                  <button
                    type="button"
                    onClick={(event) => {
                      event.stopPropagation()
                      navigate(`/c2/scans/${item.id}`)
                    }}
                    className="inline-flex items-center gap-0.5 rounded px-1.5 py-0.5 text-xs text-cyan-300 hover:bg-cyan-400/10"
                    aria-label={`View scan ${item.id}`}
                  >
                    View <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
                  </button>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

/** Source / verdict / class selects shared by the feed and the history page. */
export function ScanFilters({ filters, onChange, idPrefix }) {
  const set = (key) => (value) => onChange({ ...filters, [key]: value })
  return (
    <div className="flex flex-wrap gap-3">
      <SelectField
        id={`${idPrefix}-source`}
        label="Source"
        value={filters.source}
        onChange={set('source')}
        options={[{ value: '', label: 'All sources' }, ...Object.entries(SOURCE_LABELS).map(([value, label]) => ({ value, label }))]}
      />
      <SelectField
        id={`${idPrefix}-verdict`}
        label="Verdict"
        value={filters.verdict}
        onChange={set('verdict')}
        options={[
          { value: '', label: 'All verdicts' },
          { value: 'Malicious', label: 'Malicious' },
          { value: 'Suspicious', label: 'Suspicious' },
          { value: 'Legitimate', label: 'Legitimate' },
          { value: 'none', label: 'No verdict' },
        ]}
      />
      <SelectField
        id={`${idPrefix}-class`}
        label="Threat class"
        value={filters.threat_class}
        onChange={set('threat_class')}
        options={[{ value: '', label: 'All classes' }, ...CLASSES.map((value) => ({ value, label: CLASS_LABELS[value] }))]}
      />
    </div>
  )
}
