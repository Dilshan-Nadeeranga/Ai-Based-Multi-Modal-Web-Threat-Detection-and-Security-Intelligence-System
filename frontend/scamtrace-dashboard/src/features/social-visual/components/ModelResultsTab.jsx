import { useEffect, useState } from 'react'
import { Boxes, Brain, Gauge, Info, Loader2, Newspaper, ScanSearch, Tags } from 'lucide-react'
import { getModelResults } from '../api/socialVisualApi.js'
import { pct } from './constants.js'
import { Card } from './ui.jsx'

const BLUE = '0, 116, 221'

function Section({ title, children }) {
  return (
    <div className="mt-5">
      <p className="mb-2 text-[11px] uppercase tracking-wide text-st-muted">{title}</p>
      {children}
    </div>
  )
}

function MetricTiles({ rows }) {
  return (
    <div className="grid grid-cols-2 gap-3">
      {rows.map(([label, value]) => (
        <div key={label} className="rounded-lg bg-st-low border border-st-container p-3">
          <p className="text-[11px] uppercase text-st-muted leading-tight">{label}</p>
          <p className="mt-1 text-xl font-bold text-st-ink">{pct(value, 1)}</p>
          <div className="mt-2 h-1.5 rounded bg-st-container overflow-hidden">
            <div className="st-bar h-full bg-st-blue" style={{ width: `${Math.max(0, Math.min(1, value || 0)) * 100}%` }} />
          </div>
        </div>
      ))}
    </div>
  )
}

function ClassBars({ perClass }) {
  return (
    <div className="space-y-2">
      {Object.entries(perClass || {}).map(([label, m]) => (
        <div key={label}>
          <div className="flex justify-between text-xs text-st-ink">
            <span>{label.replaceAll('_', ' ')} <span className="text-st-muted">· n={m.support}</span></span>
            <span className="font-mono">{pct(m.f1, 1)}</span>
          </div>
          <div className="mt-1 h-2 rounded bg-st-container overflow-hidden">
            <div className="st-bar h-full bg-st-blue" style={{ width: `${(m.f1 || 0) * 100}%` }} />
          </div>
        </div>
      ))}
    </div>
  )
}

function ConfusionMatrix({ matrix }) {
  if (!matrix) return null
  const rows = matrix.rows_true_cols_pred
  const name = (label) => label.replaceAll('_', ' ')
  return (
    <div className="overflow-x-auto">
      <table className="text-xs text-st-ink border-separate border-spacing-1">
        <thead>
          <tr>
            <th className="text-left font-normal text-st-muted pr-2">Actual ↓ / Predicted →</th>
            {matrix.labels.map((label) => <th key={label} className="px-1 font-medium text-st-muted capitalize">{name(label)}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => {
            const total = row.reduce((sum, v) => sum + v, 0) || 1
            return (
              <tr key={matrix.labels[i]}>
                <td className="pr-2 font-medium text-st-muted capitalize whitespace-nowrap">{name(matrix.labels[i])}</td>
                {row.map((value, j) => {
                  const share = value / total
                  return (
                    <td key={j} title={`${value} of ${total} (${pct(share)})`}
                        className={`min-w-14 rounded-md px-3 py-2 text-center font-mono font-semibold ${i === j ? 'ring-2 ring-st-blue/40' : ''}`}
                        style={{ backgroundColor: `rgba(${BLUE}, ${0.06 + share * 0.74})`, color: share > 0.5 ? '#fff' : undefined }}>
                      {value}
                    </td>
                  )
                })}
              </tr>
            )
          })}
        </tbody>
      </table>
      <p className="mt-1 text-[11px] text-st-muted">Diagonal (outlined) = correct predictions. Shading = share of each actual class.</p>
    </div>
  )
}

function Chips({ items }) {
  return (
    <div className="flex flex-wrap gap-2">
      {items.map(([label, value]) => (
        <span key={label} className="inline-flex items-center gap-2 rounded-full bg-st-low px-3 py-1 text-xs text-st-ink ring-1 ring-st-container">
          {label}
          {value !== undefined && <span className="font-mono font-semibold text-st-blue-dark">{value}</span>}
        </span>
      ))}
    </div>
  )
}

function Note({ children }) {
  return (
    <div className="mt-5 flex gap-2 rounded-lg bg-st-low p-3 text-xs text-st-muted ring-1 ring-st-container">
      <Info className="mt-0.5 h-4 w-4 shrink-0 text-st-blue-dark" />
      <p>{children}</p>
    </div>
  )
}

function ClassifierCard({ title, icon, data, missing }) {
  if (!data) return <Card title={title} icon={icon}><p className="text-sm text-st-muted italic">{missing}</p></Card>
  return (
    <Card title={title} icon={icon} subtitle={`${data.model} · best epoch ${data.best_epoch} · held-out test split`}>
      <MetricTiles rows={[['Accuracy', data.test?.accuracy], ['Macro F1', data.test?.macro?.f1]]} />
      <Section title="F1 per class"><ClassBars perClass={data.test?.per_class} /></Section>
      <Section title="Confusion matrix (test)"><ConfusionMatrix matrix={data.test?.confusion_matrix} /></Section>
      {data.unlabelled_categories?.length > 0 && (
        <Section title="No labelled samples (rule-based in the live analyzer)">
          <Chips items={data.unlabelled_categories.map((c) => [c.replaceAll('_', ' ')])} />
        </Section>
      )}
      {data.notes && <Note>{data.notes}</Note>}
    </Card>
  )
}

export default function ModelResultsTab() {
  const [results, setResults] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    getModelResults().then(setResults).catch((err) => setError(err.message))
  }, [])

  if (error) return <p role="alert" className="rounded-lg bg-st-error-bg p-4 text-sm text-st-error-ink">{error}</p>
  if (!results) return <p className="flex items-center gap-2 text-sm text-st-muted"><Loader2 className="w-4 h-4 animate-spin" /> Loading model results…</p>

  const { text_baseline: text, clip_brand: clip, logo_detector: logo, risk_score: risk, consistency } = results
  const riskTest = risk.evaluation_test_split || {}
  return (
    <div className="grid md:grid-cols-2 gap-6">
      <Card title="Text threat baseline" icon={Brain} subtitle={`${text.model} · best epoch ${text.best_epoch} · held-out test split`}>
        <MetricTiles rows={[['Accuracy', text.test.accuracy], ['F1 (scam)', text.test.f1_scam],
          ['Precision (scam)', text.test.precision_scam], ['Recall (scam)', text.test.recall_scam]]} />
        <Section title="Confusion matrix (test)"><ConfusionMatrix matrix={text.confusion_matrix} /></Section>
      </Card>

      <Card title="CLIP brand recognition" icon={ScanSearch}
            subtitle={`${clip.model} · ${clip.mode} mode · threshold ${clip.threshold} · Zenodo phishing test pages`}>
        <MetricTiles rows={[['Precision', clip.zenodo_test?.precision], ['Recall', clip.zenodo_test?.recall],
          ['F1', clip.zenodo_test?.f1], ['Unknown-brand rejection', clip.zenodo_test?.unknown_rejection_rate],
          ['Closed-set top-1', clip.zenodo_test?.closed_set_top1], ['Closed-set top-3', clip.zenodo_test?.closed_set_top3]]} />
        {clip.b32_zenodo_test && (
          <Section title="Model comparison (F1)">
            <Chips items={[['ViT-B/16 (selected)', pct(clip.zenodo_test?.f1, 1)], ['ViT-B/32', pct(clip.b32_zenodo_test.f1, 1)]]} />
          </Section>
        )}
      </Card>

      <Card title="Logo detector" icon={Boxes}
            subtitle={`${logo.config?.weights} · ${logo.config?.epochs} epochs · imgsz ${logo.config?.imgsz} · test split`}>
        <MetricTiles rows={[['Precision', logo.metrics?.test?.precision], ['Recall', logo.metrics?.test?.recall],
          ['mAP@50', logo.metrics?.test?.mAP50], ['mAP@50-95', logo.metrics?.test?.mAP50_95]]} />
        <Section title="Brand matching F1">
          <MetricTiles rows={[['Detected crops', logo.brand_matching_test?.synthetic_detected?.f1],
            ['Real webpages', logo.brand_matching_test?.dom_page?.f1]]} />
        </Section>
      </Card>

      <Card title="Preliminary risk score" icon={Gauge} subtitle={`Test split, n = ${riskTest.n}`}>
        <MetricTiles rows={[['ROC-AUC (fused score)', riskTest.auc?.score?.auc],
          ['Scam recall (MEDIUM + HIGH)', riskTest.high_or_medium_recall_scam],
          ['HIGH precision', riskTest.high_precision],
          ['Brand-mismatch precision', consistency.brand_mismatch_as_scam_signal?.precision]]} />
        <Section title="Risk levels over all samples">
          <Chips items={Object.entries(risk.level_counts || {})} />
        </Section>
      </Card>

      <ClassifierCard title="Threat category model" icon={Tags} data={results.threat_category}
                      missing="Not trained yet. Run scripts/train_threat_category.py --task category." />
      <ClassifierCard title="Misinformation model" icon={Newspaper} data={results.misinformation}
                      missing="Not trained yet. Run scripts/train_threat_category.py --task misinformation." />
    </div>
  )
}
