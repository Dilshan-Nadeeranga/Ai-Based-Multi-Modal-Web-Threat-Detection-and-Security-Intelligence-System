import { ScanText } from 'lucide-react'
import { Card, Check, Field, NotAvailable } from './ui.jsx'

export default function OCRAnalysisCard({ ocr, preprocessing }) {
  return (
    <Card title="OCR analysis" subtitle="Tesseract OCR on the preprocessed post image" icon={ScanText}>
      {!ocr ? <NotAvailable>OCR not run — no valid post image.</NotAvailable> : (
        <div className="grid md:grid-cols-2 gap-6">
          <div className="space-y-3">
            <p className="text-[11px] uppercase tracking-wide text-st-muted">Extracted text</p>
            <pre className="whitespace-pre-wrap text-sm text-st-ink font-mono rounded-lg bg-st-low border border-st-container p-3 max-h-56 overflow-auto">
              {ocr.text || '(no text found)'}
            </pre>
            <div className="grid grid-cols-3 gap-4">
              <Field label="Confidence">{ocr.average_confidence === null ? '—' : `${ocr.average_confidence.toFixed(1)}%`}</Field>
              <Field label="Words">{ocr.word_count}</Field>
              <Field label="Language">{ocr.used_languages}</Field>
            </div>
            {ocr.warning && <p className="text-xs text-amber-700">{ocr.warning}</p>}
          </div>
          <div>
            <p className="text-[11px] uppercase tracking-wide text-st-muted mb-2">Preprocessing checks</p>
            <ul className="space-y-1.5">
              {(preprocessing?.checks || []).map((check) => (
                <Check key={check.label} ok={check.ok}>
                  {check.label} <span className="text-st-muted">— {check.detail}</span>
                </Check>
              ))}
            </ul>
          </div>
        </div>
      )}
    </Card>
  )
}
