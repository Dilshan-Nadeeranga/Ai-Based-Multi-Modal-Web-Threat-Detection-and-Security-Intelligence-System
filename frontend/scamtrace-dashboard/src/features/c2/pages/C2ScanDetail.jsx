import { useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import { getScan } from '../api/c2Api.js'
import ResultView from '../components/ResultView.jsx'
import { StateBox } from '../components/ui.jsx'
import { loadDemo } from '../demo/demoData.js'
import { useAsyncData } from '../hooks/useAsyncData.js'
import { useDemoMode } from '../hooks/useDemoMode.js'

/** One stored scan (GET /api/v1/scans/{id}) in the same result view as the Scan page. */
export default function C2ScanDetail() {
  const { scanId } = useParams()
  const navigate = useNavigate()
  const { demo } = useDemoMode()
  const { data, error, loading, reload } = useAsyncData(async (signal) => {
    if (demo) {
      const { details } = await loadDemo()
      const found = details[scanId]
      if (!found) throw new Error('This scan is not part of the bundled demo set.')
      return found
    }
    return getScan(scanId, { signal })
  }, `${demo}|${scanId}`)

  return (
    <div className="flex flex-col gap-4">
      <button
        type="button"
        onClick={() => (window.history.length > 1 ? navigate(-1) : navigate('/c2/history'))}
        className="inline-flex w-fit items-center gap-1.5 text-sm text-cyan-300 hover:text-cyan-100"
      >
        <ArrowLeft className="h-4 w-4" aria-hidden="true" /> Back
      </button>
      <h2 className="font-mono text-lg text-slate-50">Scan #{scanId}</h2>
      {!data && loading && <StateBox state="loading" message="Loading the stored analysis…" />}
      {error && <StateBox state="error" message={error.message} onRetry={error.status === 404 ? undefined : reload} />}
      {data && !error && <ResultView result={data} />}
    </div>
  )
}
