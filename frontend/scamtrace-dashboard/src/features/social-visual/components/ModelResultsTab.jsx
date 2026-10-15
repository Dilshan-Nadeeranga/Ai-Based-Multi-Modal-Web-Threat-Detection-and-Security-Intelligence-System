import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { getModelResults } from '../api/socialVisualApi.js'
import { pct } from './constants.js'
import { Card } from './ui.jsx'

function Metrics({ rows }) {
  return (
    <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
      {rows.map(([label, value, raw]) => (
        <div key={label} className="flex justify-between border-b border-slate-800 py-1">
          <dt className="text-slate-400">{label}</dt>
          <dd className="font-mono text-slate-100">{raw ? (value ?? '—') : pct(value, 1)}</dd>
        </div>
      ))}
    </dl>
  )
}

export default function ModelResultsTab() {
  const [results, setResults] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    getModelResults().then(setResults).catch((err) => setError(err.message))
  }, [])

  if (error) return <p className="text-sm text-red-400">{error}</p>
  if (!results) return <p className="flex items-center gap-2 text-sm text-slate-400"><Loader2 className="w-4 h-4 animate-spin" /> Loading model results…</p>

  const { text_baseline: text, clip_brand: clip, logo_detector: logo, risk_score: risk, consistency } = results
  const matrix = text.confusion_matrix
  return (
    <div className="grid md:grid-cols-2 gap-6">
      <Card title="Text threat baseline" subtitle={`${text.model} · best epoch ${text.best_epoch} · held-out test split`}>
        <Metrics rows={[['Accuracy', text.test.accuracy], ['Precision (scam)', text.test.precision_scam],
          ['Recall (scam)', text.test.recall_scam], ['F1 (scam)', text.test.f1_scam]]} />
        {matrix && (
          <table className="mt-4 text-xs text-slate-300">
            <thead><tr><th /><th className="px-3 font-normal text-slate-500">pred legit</th><th className="px-3 font-normal text-slate-500">pred scam</th></tr></thead>
            <tbody>
              {matrix.rows_true_cols_pred.map((row, i) => (
                <tr key={i}><td className="pr-3 text-slate-500">true {matrix.labels[i]}</td>{row.map((v, j) => <td key={j} className="px-3 text-center font-mono">{v}</td>)}</tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <Card title="CLIP brand recognition" subtitle={`${clip.model} · ${clip.mode} mode · threshold ${clip.threshold} · Zenodo phishing test pages`}>
        <Metrics rows={[['Precision', clip.zenodo_test?.precision], ['Recall', clip.zenodo_test?.recall],
          ['F1', clip.zenodo_test?.f1], ['Unknown-brand rejection', clip.zenodo_test?.unknown_rejection_rate],
          ['Closed-set top-1', clip.zenodo_test?.closed_set_top1], ['Closed-set top-3', clip.zenodo_test?.closed_set_top3]]} />
        {clip.b32_zenodo_test && <p className="mt-3 text-xs text-slate-500">ViT-B/32 comparison F1: {pct(clip.b32_zenodo_test.f1, 1)}</p>}
      </Card>

      <Card title="Logo detector" subtitle={`${logo.config?.weights} · ${logo.config?.epochs} epochs · imgsz ${logo.config?.imgsz} · test split`}>
        <Metrics rows={[['Precision', logo.metrics?.test?.precision], ['Recall', logo.metrics?.test?.recall],
          ['mAP@50', logo.metrics?.test?.mAP50], ['mAP@50-95', logo.metrics?.test?.mAP50_95],
          ['Brand match F1 (detected crops)', logo.brand_matching_test?.synthetic_detected?.f1],
          ['Brand match F1 (real pages)', logo.brand_matching_test?.dom_page?.f1]]} />
      </Card>

      <Card title="Preliminary risk score" subtitle={`Test split, n = ${risk.evaluation_test_split?.n}`}>
        <Metrics rows={[['ROC-AUC (fused score)', risk.evaluation_test_split?.auc?.score?.auc],
          ['Scam recall (MEDIUM+HIGH)', risk.evaluation_test_split?.high_or_medium_recall_scam],
          ['HIGH precision', risk.evaluation_test_split?.high_precision],
          ['Brand-mismatch precision', consistency.brand_mismatch_as_scam_signal?.precision]]} />
        <p className="mt-3 text-xs text-slate-500">
          Levels over all samples: {Object.entries(risk.level_counts || {}).map(([k, v]) => `${k} ${v}`).join(' · ')}
        </p>
      </Card>

      <ClassifierCard title="Threat category model" data={results.threat_category}
                      missing="Not trained yet. Run scripts/train_threat_category.py --task category." />
      <ClassifierCard title="Misinformation model" data={results.misinformation}
                      missing="Not trained yet. Run scripts/train_threat_category.py --task misinformation." />
    </div>
  )
}

function ClassifierCard({ title, data, missing }) {
  if (!data) return <Card title={title}><p className="text-sm text-slate-500 italic">{missing}</p></Card>
  const matrix = data.test?.confusion_matrix
  return (
    <Card title={title} subtitle={`${data.model} · best epoch ${data.best_epoch} · held-out test split`}>
      <Metrics rows={[['Accuracy', data.test?.accuracy], ['Macro F1', data.test?.macro?.f1],
        ...Object.entries(data.test?.per_class || {}).map(([label, m]) => [`F1 ${label} (n=${m.support})`, m.f1])]} />
      {matrix && (
        <table className="mt-4 text-xs text-slate-300">
          <thead><tr><th />{matrix.labels.map((l) => <th key={l} className="px-2 font-normal text-slate-500">pred {l}</th>)}</tr></thead>
          <tbody>
            {matrix.rows_true_cols_pred.map((row, i) => (
              <tr key={i}><td className="pr-3 text-slate-500">true {matrix.labels[i]}</td>{row.map((v, j) => <td key={j} className="px-2 text-center font-mono">{v}</td>)}</tr>
            ))}
          </tbody>
        </table>
      )}
      {data.unlabelled_categories?.length > 0 && (
        <p className="mt-3 text-xs text-slate-500">No labelled samples (rule-based in the live analyzer): {data.unlabelled_categories.join(', ')}.</p>
      )}
      {data.notes && <p className="mt-2 text-xs text-slate-500">{data.notes}</p>}
    </Card>
  )
}
