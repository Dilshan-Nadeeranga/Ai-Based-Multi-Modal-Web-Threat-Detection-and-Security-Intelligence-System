import { useEffect, useState } from 'react'
import { CheckCircle2, Circle, Loader2, MinusCircle, XCircle } from 'lucide-react'
import { PIPELINE_STEPS } from './constants.js'
import { Card } from './ui.jsx'

const ICONS = {
  done: <CheckCircle2 className="w-4 h-4 text-emerald-700" />,
  skipped: <MinusCircle className="w-4 h-4 text-st-muted" />,
  failed: <XCircle className="w-4 h-4 text-red-700" />,
  running: <Loader2 className="w-4 h-4 text-st-blue-dark animate-spin" />,
  pending: <Circle className="w-4 h-4 text-st-outline" />,
}

/** While running, the backend gives no per-step progress, so every step shows as "running" until the response arrives. */
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

  return (
    <Card title="Analysis pipeline"
          subtitle={running ? `Running on the C3 service… ${elapsed.toFixed(1)} s (first run also loads the models)`
                            : `Completed in ${(total / 1000).toFixed(1)} s of processing`}>
      <ol className="grid sm:grid-cols-3 gap-2">
        {PIPELINE_STEPS.map(({ key, label }) => {
          const step = byKey[key]
          const status = step?.status || (running ? 'running' : 'pending')
          return (
            <li key={key} className="flex items-start gap-2 rounded-lg bg-st-low border border-st-container px-3 py-2">
              <span className="mt-0.5">{ICONS[status]}</span>
              <div className="min-w-0">
                <p className="text-sm text-st-ink">{label}</p>
                <p className="text-[11px] text-st-muted truncate" title={step?.detail || ''}>
                  {status === 'done' && `${step.duration_ms} ms`}
                  {status === 'skipped' && `skipped — ${step.detail}`}
                  {status === 'failed' && `failed — ${step.detail}`}
                  {status === 'running' && 'running'}
                </p>
              </div>
            </li>
          )
        })}
      </ol>
    </Card>
  )
}
