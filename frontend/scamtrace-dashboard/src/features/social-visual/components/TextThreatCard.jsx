import { MessageSquareWarning } from 'lucide-react'
import { Bar, Card, NotAvailable } from './ui.jsx'

function prediction(score) {
  if (score === null || score === undefined) return null
  return score >= 0.5 ? 'scam' : 'legitimate'
}

export default function TextThreatCard({ textThreat }) {
  return (
    <Card title="Text threat analysis" subtitle={textThreat?.model} icon={MessageSquareWarning}>
      {!textThreat ? <NotAvailable>No post text or OCR text to classify.</NotAvailable> : (
        <div className="space-y-4">
          {[['Post text', textThreat.post_text_score], ['OCR text', textThreat.ocr_text_score]].map(([label, score]) => (
            <div key={label}>
              {score === null || score === undefined
                ? <p className="text-xs text-slate-500">{label}: not available</p>
                : <Bar label={`${label} scam probability`} value={score}
                       hint={`Prediction: ${prediction(score)} (threshold 50%)`} />}
            </div>
          ))}
        </div>
      )}
    </Card>
  )
}
