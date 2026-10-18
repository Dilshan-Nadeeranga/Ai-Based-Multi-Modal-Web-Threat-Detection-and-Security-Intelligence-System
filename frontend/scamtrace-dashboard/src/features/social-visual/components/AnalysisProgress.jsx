import { useEffect, useState } from 'react'
import { CheckCircle2, Circle, Loader2, MinusCircle, XCircle } from 'lucide-react'
import { PIPELINE_STEPS } from './constants.js'
import { Card } from './ui.jsx'

const ICONS = {
  done: <CheckCircle2 className="st-pop w-4 h-4 text-st-blue-dark" />,
  skipped: <MinusCircle className="st-pop w-4 h-4 text-st-muted" />,
  failed: <XCircle className="st-pop w-4 h-4 text-red-700" />,
  running: <Loader2 className="w-4 h-4 text-st-blue-dark animate-spin" />,
  pending: <Circle className="w-4 h-4 text-st-fixed-dim" />,
}

/** `pipeline` holds the steps reported so far (streamed while running, the final list afterwards). */
export default function AnalysisProgress({ running, pipeline }) {
  const [elapsed, setElapsed] = useState(0)

  useEffect(() => {
    if (!running) return undefined
    const started = Date.now()
    const timer = setInterval(() => setElapsed((Date.now() - started) / 1000), 200)
    return () => clearInterval(timer)
  }, [running])

  const byKey = Object.fromEntries((pipeline || []).map((step) => [step.key, step]))
  const total = (pipeline || []).reduce((sum, step) => sum + (step.duration_ms || 0), 0)
  const finished = (pipeline || []).filter((step) => step.status !== 'running').length
  const subtitle = !running
    ? `Completed in ${(total / 1000).toFixed(1)} s of processing`
    : finished === 0 && !(pipeline || []).length
      ? `Starting on the C3 service… ${elapsed.toFixed(1)} s (the first run also loads the models)`
      : `Running… ${finished} of ${PIPELINE_STEPS.length} steps finished · ${elapsed.toFixed(1)} s`

  return (
    <Card title="Analysis pipeline" subtitle={subtitle}>
      <ol className="st-stagger grid sm:grid-cols-3 gap-2">
        {PIPELINE_STEPS.map(({ key, label }) => {
          const step = byKey[key]
          const status = step?.status || 'pending'
          return (
            <li key={key} className="flex items-start gap-2 rounded-lg bg-st-low border border-st-container px-3 py-2">
              <span className="mt-0.5">{ICONS[status]}</span>
              <div className="min-w-0">
                <p className={`text-sm ${status === 'pending' ? 'text-st-muted' : 'text-st-ink'}`}>{label}</p>
                <p className="text-[11px] text-st-muted truncate" title={step?.detail || ''}>
                  {status === 'done' && `${step.duration_ms} ms`}
                  {status === 'skipped' && `skipped — ${step.detail}`}
                  {status === 'failed' && `failed — ${step.detail}`}
                  {status === 'running' && 'running…'}
                  {status === 'pending' && (running ? 'waiting' : 'not run')}
                </p>
              </div>
            </li>
          )
        })}
      </ol>
    </Card>
  )
}
