import { ScanText } from 'lucide-react'
import { Card, Check, Field, NotAvailable } from './ui.jsx'

export default function OCRAnalysisCard({ ocr, preprocessing }) {
  return (
    <Card title="OCR analysis" subtitle="Tesseract OCR on the preprocessed post image" icon={ScanText}>
      {!ocr ? <NotAvailable>OCR not run — no valid post image.</NotAvailable> : (
        <div className="grid md:grid-cols-2 gap-6">
          <div className="space-y-3">
            <p className="text-[11px] uppercase tracking-wide text-slate-500">Extracted text</p>
            <pre className="whitespace-pre-wrap text-sm text-slate-200 font-mono rounded-lg bg-slate-950/60 border border-slate-800 p-3 max-h-56 overflow-auto">
              {ocr.text || '(no text found)'}
            </pre>
            <div className="grid grid-cols-3 gap-4">
              <Field label="Confidence">{ocr.average_confidence === null ? '—' : `${ocr.average_confidence.toFixed(1)}%`}</Field>
              <Field label="Words">{ocr.word_count}</Field>
              <Field label="Language">{ocr.used_languages}</Field>
            </div>
            {ocr.warning && <p className="text-xs text-amber-400">{ocr.warning}</p>}
          </div>
          <div>
            <p className="text-[11px] uppercase tracking-wide text-slate-500 mb-2">Preprocessing checks</p>
            <ul className="space-y-1.5">
              {(preprocessing?.checks || []).map((check) => (
                <Check key={check.label} ok={check.ok}>
                  {check.label} <span className="text-slate-500">— {check.detail}</span>
                </Check>
              ))}
            </ul>
          </div>
        </div>
      )}
    </Card>
  )
}
