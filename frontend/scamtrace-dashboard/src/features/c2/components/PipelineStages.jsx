import { useEffect, useMemo, useState } from 'react'
import { CheckCircle2, CircleDashed, CircleSlash, Loader2, XCircle } from 'lucide-react'
import { defangUrl } from '../api/defang.js'
import { PIPELINE_STAGES } from '../constants.js'

const STEP_MS = 420 // animation pace while waiting (the API answers once, at the end)

function stageOutcome(stage, result) {
  const timings = result.timings_ms || {}
  const ms = stage.keys.reduce((sum, key) => sum + (timings[key] || 0), 0)
  const ran = stage.keys.some((key) => key in timings)
  const modalities = result.modalities || {}
  const failedModality =
    (stage.id === 'dom' && modalities.dom?.status === 'failed') ||
    ((stage.id === 'content' || stage.id === 'text') && modalities.content?.status === 'failed') ||
    ((stage.id === 'js' || stage.id === 'behavior') && modalities.behavior?.status === 'failed')
  if (stage.id === 'fetch' && result.input?.mode === 'html') {
    return { state: 'skipped', ms: null, note: result.demo ? 'recorded page (demo) — no network used' : 'pasted HTML — nothing fetched' }
  }
  if (failedModality) return { state: 'failed', ms: ran ? ms : null, note: 'failed — other arms fused (degraded)' }
  if (!ran) return { state: 'skipped', ms: null, note: result.status === 'ok' ? 'not needed' : 'not run — no page to analyze' }
  if (stage.id === 'fetch' && result.status === 'unreachable') return { state: 'failed', ms, note: 'page could not be fetched' }
  return { state: 'done', ms, note: stage.note }
}

const ICON = {
  done: <CheckCircle2 className="h-4 w-4 text-emerald-300" aria-hidden="true" />,
  running: <Loader2 className="h-4 w-4 animate-spin text-cyan-300 motion-reduce:animate-none" aria-hidden="true" />,
  queued: <CircleDashed className="h-4 w-4 text-slate-500" aria-hidden="true" />,
  skipped: <CircleSlash className="h-4 w-4 text-slate-400" aria-hidden="true" />,
  failed: <XCircle className="h-4 w-4 text-amber-300" aria-hidden="true" />,
}

function useElapsed(running, startedAt) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!running) return undefined
    const id = setInterval(() => setNow(Date.now()), 120)
    return () => clearInterval(id)
  }, [running])
  return running && startedAt ? Math.max(0, now - startedAt) : 0
}

/**
 * The 9B-1 orchestrator's real stages in order. While waiting, a highlight walks through them
 * (labelled as in progress); when the answer arrives every stage shows its REAL time from
 * timings_ms, or why it was skipped / failed.
 */
export default function PipelineStages({ running, startedAt, result, target }) {
  const elapsed = useElapsed(running, startedAt)
  const active = Math.min(PIPELINE_STAGES.length - 1, Math.floor(elapsed / STEP_MS))

  const rows = useMemo(
    () =>
      PIPELINE_STAGES.map((stage, index) => {
        if (result) return { stage, ...stageOutcome(stage, result) }
        if (!running) return { stage, state: 'queued', ms: null, note: stage.note }
        return { stage, state: index < active ? 'passed' : index === active ? 'running' : 'queued', ms: null, note: stage.note }
      }),
    [result, running, active],
  )

  const log = useMemo(() => {
    const lines = [`$ c2 analyze ${target ? defangUrl(target) : '(pasted HTML)'}`]
    if (running && !result) {
      PIPELINE_STAGES.slice(0, active + 1).forEach((stage) => lines.push(`… ${stage.id.padEnd(10)} ${stage.note}`))
      lines.push(`  waiting for C2 · ${(elapsed / 1000).toFixed(1)} s`)
    }
    if (result) {
      rows.forEach(({ stage, state, ms, note }) => {
        const mark = { done: '✓', skipped: '–', failed: '✗' }[state] || ' '
        const time = ms === null || ms === undefined ? '      —' : `${ms.toFixed(1).padStart(7)} ms`
        lines.push(`${mark} ${stage.id.padEnd(10)} ${time}  ${note}`)
      })
      const verdict = result.verdict ? `${result.verdict} · ${result.threat_class} · risk ${result.risk_score}` : `status ${result.status}`
      lines.push(`= ${verdict} · total ${(result.timings_ms?.total ?? 0).toFixed(0)} ms${result.degraded ? ' · DEGRADED' : ''}`)
    }
    return lines
  }, [rows, running, result, active, elapsed, target])

  const total = result?.timings_ms?.total
  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
      <ol className="flex flex-col gap-1.5" aria-label="Analysis pipeline">
        {rows.map(({ stage, state, ms, note }, index) => {
          const shown = state === 'passed' ? 'running' : state
          const width = total && ms ? Math.max(2, (ms / total) * 100) : 0
          return (
            <li
              key={stage.id}
              className={`relative grid grid-cols-[1.5rem_1.25rem_1fr_auto] items-center gap-2 overflow-hidden rounded-md border px-2.5 py-1.5 ${
                state === 'running' ? 'c2-stage-running border-cyan-400/50' : 'border-slate-800'
              } ${state === 'queued' ? 'opacity-60' : ''}`}
            >
              <span className="font-mono text-xs text-slate-500">{String(index + 1).padStart(2, '0')}</span>
              {ICON[shown]}
              <span className="min-w-0">
                <span className="block text-sm font-medium text-slate-100">{stage.label}</span>
                <span className="block truncate text-xs text-slate-400">{note}</span>
              </span>
              <span className="font-mono text-xs text-slate-200">{ms !== null && ms !== undefined ? `${ms.toFixed(1)} ms` : ''}</span>
              {width > 0 && <span className="absolute bottom-0 left-0 h-0.5 bg-cyan-400/70" style={{ width: `${width}%` }} aria-hidden="true" />}
            </li>
          )
        })}
      </ol>
      <div className="flex min-h-[17rem] flex-col rounded-lg border border-slate-800 bg-black/70">
        <div className="flex items-center gap-1.5 border-b border-slate-800 px-3 py-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-red-400/70" aria-hidden="true" />
          <span className="h-2.5 w-2.5 rounded-full bg-amber-300/70" aria-hidden="true" />
          <span className="h-2.5 w-2.5 rounded-full bg-emerald-400/70" aria-hidden="true" />
          <span className="ml-2 font-mono text-[0.6875rem] text-slate-400">scan.log</span>
        </div>
        <pre
          className="flex-1 overflow-auto whitespace-pre-wrap break-words p-3 font-mono text-xs leading-relaxed text-emerald-200"
          aria-label="Scan log"
          tabIndex={0}
        >
          {log.join('\n')}
          {running && !result && <span className="c2-cursor" />}
        </pre>
      </div>
    </div>
  )
}
