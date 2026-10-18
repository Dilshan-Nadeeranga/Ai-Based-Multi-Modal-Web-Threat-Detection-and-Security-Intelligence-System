import { CheckCircle2, ScanText, XCircle } from 'lucide-react'
import { Card, NotAvailable } from './ui.jsx'

function Stat({ label, value, bar }) {
  return (
    <div className="min-w-0 rounded-lg bg-st-low px-3 py-2.5 ring-1 ring-st-container">
      <p className="text-[11px] uppercase tracking-wide text-st-muted">{label}</p>
      <p className="mt-0.5 truncate text-base font-semibold text-st-ink">{value}</p>
      {bar !== undefined && (
        <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-st-container">
          <div className="st-bar h-full rounded-full bg-st-blue" style={{ width: `${Math.max(0, Math.min(100, bar))}%` }} />
        </div>
      )}
    </div>
  )
}

export default function OCRAnalysisCard({ ocr, preprocessing }) {
  const confidence = ocr?.average_confidence
  const lines = ocr?.text ? ocr.text.split('\n').filter((line) => line.trim()).length : 0
  const checks = preprocessing?.checks || []

  return (
    <Card title="OCR analysis" subtitle="Tesseract OCR on the preprocessed post image" icon={ScanText}>
      {!ocr ? <NotAvailable>OCR not run — no valid post image.</NotAvailable> : (
        <div className="space-y-5">
          <div className="grid grid-cols-3 gap-2">
            <Stat label="Confidence" value={confidence === null ? '—' : `${confidence.toFixed(1)}%`} bar={confidence ?? 0} />
            <Stat label="Words" value={ocr.word_count} />
            <Stat label="Language" value={ocr.used_languages} />
          </div>

          <div>
            <div className="mb-1.5 flex items-baseline justify-between">
              <p className="text-[11px] uppercase tracking-wide text-st-muted">Extracted text</p>
              {lines > 0 && <span className="text-[11px] text-st-muted">{lines} lines</span>}
            </div>
            <pre className="st-scroll max-h-48 overflow-auto whitespace-pre-wrap rounded-lg bg-st-low p-3 font-mono text-[13px] leading-relaxed text-st-ink ring-1 ring-st-container">
              {ocr.text || <span className="font-inter italic text-st-muted">No text found in the image.</span>}
            </pre>
          </div>

          {checks.length > 0 && (
            <div>
              <p className="mb-1.5 text-[11px] uppercase tracking-wide text-st-muted">
                Preprocessing checks · {checks.filter((c) => c.ok).length}/{checks.length} passed
              </p>
              <ul className="divide-y divide-st-container rounded-lg ring-1 ring-st-container">
                {checks.map((check) => (
                  <li key={check.label} className="flex items-center gap-2 px-3 py-1.5 text-sm">
                    {check.ok
                      ? <CheckCircle2 className="st-pop h-4 w-4 shrink-0 text-emerald-600" aria-hidden="true" />
                      : <XCircle className="st-pop h-4 w-4 shrink-0 text-red-600" aria-hidden="true" />}
                    <span className="text-st-ink">{check.label}</span>
                    <span className="ml-auto truncate pl-2 text-right text-xs text-st-muted" title={check.detail}>{check.detail}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </Card>
  )
}
