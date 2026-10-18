import { BarChart3, Boxes, Database, FlaskConical, Network, Target } from 'lucide-react'
import { getResearch } from '../api/c2Api.js'
import ArchitectureDiagram from '../components/ArchitectureDiagram.jsx'
import { CiBarChart } from '../components/Charts.jsx'
import { Panel, StateBox } from '../components/ui.jsx'
import { ARM_LABELS, CLASSES, CLASS_LABELS, LANGUAGE_LABELS, num, pct } from '../constants.js'
import { loadDemo } from '../demo/demoData.js'
import { useAsyncData } from '../hooks/useAsyncData.js'
import { useDemoMode } from '../hooks/useDemoMode.js'

const LANGS = ['en', 'si', 'ta', 'mixed', 'unknown']
const th = 'border-b border-slate-700 px-2 py-2 text-left font-mono text-[0.6875rem] font-medium uppercase tracking-wider text-slate-400'
const td = 'whitespace-nowrap border-b border-slate-800/70 px-2 py-1.5'

function DatasetTable({ dataset }) {
  const cross = dataset.label_by_language || {}
  const used = LANGS.filter((lang) => CLASSES.some((label) => cross[label]?.[lang]))
  const languages = used.length ? used : LANGS
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[520px] border-separate border-spacing-0 text-sm">
        <caption className="mb-2 text-left text-xs text-slate-400">
          Frozen dataset {dataset.version}: {dataset.total} pages (clean view, one page per near-duplicate cluster).
        </caption>
        <thead>
          <tr>
            <th scope="col" className={th}>Class</th>
            {languages.map((lang) => (
              <th key={lang} scope="col" className={`${th} text-right`}>{LANGUAGE_LABELS[lang] || lang}</th>
            ))}
            <th scope="col" className={`${th} text-right`}>Total</th>
          </tr>
        </thead>
        <tbody>
          {CLASSES.map((label) => (
            <tr key={label}>
              <th scope="row" className={`${td} text-left font-medium text-slate-200`}>{CLASS_LABELS[label]}</th>
              {languages.map((lang) => (
                <td key={lang} className={`${td} text-right font-mono ${cross[label]?.[lang] ? 'text-slate-100' : 'text-slate-600'}`}>
                  {cross[label]?.[lang] || 0}
                </td>
              ))}
              <td className={`${td} text-right font-mono font-semibold text-cyan-200`}>{dataset.counts_per_label?.[label] ?? '—'}</td>
            </tr>
          ))}
          <tr>
            <th scope="row" className="px-2 py-1.5 text-left font-semibold text-slate-100">Total</th>
            {languages.map((lang) => (
              <td key={lang} className="px-2 py-1.5 text-right font-mono font-semibold text-cyan-200">{dataset.counts_per_language?.[lang] ?? 0}</td>
            ))}
            <td className="px-2 py-1.5 text-right font-mono font-semibold text-slate-50">{dataset.total}</td>
          </tr>
        </tbody>
      </table>
      <p className="mt-2 text-xs text-amber-200/90">
        Sinhala / Tamil pages are still few — per-language results for si / ta are reported with their (small) n.
      </p>
    </div>
  )
}

function rowLabel(row) {
  if (row.group === 'single') return row.title.replace(' single arm', '')
  return `${row.title.replace(' (TF-IDF + XLM-R)', '')} · ${row.strategy.replace('Late fusion - ', '')}`
}

function AblationTable({ ablation }) {
  const finalKey = ablation.final?.key
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[900px] border-separate border-spacing-0 text-sm">
        <caption className="mb-2 text-left text-xs text-slate-400">
          Every row on the SAME shared split: grouped 5-fold CV over train + val (choices made here), the 68 test pages predicted
          once. ✓ = strategy chosen by CV for its row; ★ = final model.
        </caption>
        <thead>
          <tr>
            <th scope="col" className={th}>Arms</th>
            <th scope="col" className={th}>Strategy</th>
            <th scope="col" className={`${th} text-right`}>CV macro-F1 ± std</th>
            <th scope="col" className={`${th} text-right`}>Test macro-F1 [95 % CI]</th>
            <th scope="col" className={`${th} text-right`}>ROC-AUC</th>
            <th scope="col" className={`${th} text-right`}>Benign FPR</th>
            <th scope="col" className={`${th} text-right`}>FPR @ ≤2 % cut</th>
          </tr>
        </thead>
        <tbody>
          {ablation.rows.map((row) => {
            const final = row.key === finalKey
            return (
              <tr key={row.key} className={final ? 'bg-emerald-400/10' : row.selected_for_row ? '' : 'text-slate-400'}>
                <td className={`${td} ${final ? 'font-semibold text-emerald-200' : 'text-slate-200'}`}>
                  {final ? '★ ' : row.selected_for_row ? '✓ ' : ''}
                  {row.title.replace(' single arm', '')}
                </td>
                <td className={`${td} text-xs`}>{row.group === 'single' ? '—' : row.strategy}</td>
                <td className={`${td} text-right font-mono`}>
                  {num(row.cv_macro_f1_mean)} ± {num(row.cv_macro_f1_std)}
                </td>
                <td className={`${td} text-right font-mono ${final ? 'text-emerald-200' : 'text-slate-100'}`}>
                  {num(row.test_macro_f1)} <span className="text-slate-400">[{num(row.test_macro_f1_ci?.[0])}, {num(row.test_macro_f1_ci?.[1])}]</span>
                </td>
                <td className={`${td} text-right font-mono`}>{num(row.test_roc_auc)}</td>
                <td className={`${td} text-right font-mono`}>{pct(row.test_benign_fpr)}</td>
                <td className={`${td} text-right font-mono`}>{pct(row.benign_fpr_at_threshold)}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function Comparison({ comparison }) {
  if (!comparison) return null
  const item = (name, data) =>
    data && (
      <li className="text-sm text-slate-300">
        Final − {name} (<span className="font-mono">{ARM_LABELS[data.single] || data.single}</span>):{' '}
        <span className="font-mono text-slate-50">{data.point >= 0 ? '+' : ''}{num(data.point)}</span>{' '}
        <span className="font-mono text-slate-400">[{num(data.ci_low)}, {num(data.ci_high)}]</span>
        {data.includes_zero ? (
          <span className="ml-2 rounded bg-amber-400/10 px-1.5 py-0.5 font-mono text-xs text-amber-200 ring-1 ring-amber-400/30">CI includes 0</span>
        ) : (
          <span className="ml-2 rounded bg-emerald-400/10 px-1.5 py-0.5 font-mono text-xs text-emerald-200 ring-1 ring-emerald-400/30">CI above 0</span>
        )}
      </li>
    )
  return (
    <ul className="mt-3 flex flex-col gap-1">
      {item('best single arm by CV', comparison.vs_best_single_by_cv)}
      {item('best single arm on test', comparison.vs_best_single_on_test)}
      <li className="text-xs text-slate-400">Paired bootstrap on the same test pages; with 68 pages an honest CI is wide.</li>
    </ul>
  )
}

function OperatingPoints({ points }) {
  const rows = []
  Object.entries(points.oof || {}).forEach(([name, block]) => {
    if (name === 'rules_fired' || !block?.with_floor) return
    rows.push({ name: `OOF ${block.with_floor.n_benign + block.with_floor.n_threat} · ${name}`, thresholds: block.thresholds, m: block.with_floor })
  })
  ;(points.test || []).forEach((run) =>
    rows.push({ name: `Test ${run.with_floor.n_benign + run.with_floor.n_threat} · ${run.xlmr ? '4 arms' : '3 arms (no XLM-R)'}`, thresholds: run.thresholds, m: run.with_floor, test: true, latency: run.latency_ms }),
  )
  if (!rows.length) return <p className="text-sm text-slate-400">No operating-point report.</p>
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[860px] border-separate border-spacing-0 text-sm">
        <caption className="mb-2 text-left text-xs text-slate-400">
          Tiers: Malicious = ≤ 2 % out-of-fold benign false-positive cut-off; Suspicious = the cut-off that still catches ≥ 95 % of
          threats (“check first”). Flagged = Suspicious or Malicious. Evidence floor included.
        </caption>
        <thead>
          <tr>
            <th scope="col" className={th}>Evaluation</th>
            <th scope="col" className={`${th} text-right`}>Suspicious ≥</th>
            <th scope="col" className={`${th} text-right`}>Malicious ≥</th>
            <th scope="col" className={`${th} text-right`}>Benign flagged</th>
            <th scope="col" className={`${th} text-right`}>Benign → Malicious</th>
            <th scope="col" className={`${th} text-right`}>Threats flagged</th>
            <th scope="col" className={`${th} text-right`}>Threats → Malicious</th>
            <th scope="col" className={`${th} text-right`}>Class acc.</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.name} className={row.test ? 'text-slate-50' : 'text-slate-300'}>
              <th scope="row" className={`${td} text-left font-medium`}>
                {row.name}
                {row.latency && <span className="block font-mono text-[0.6875rem] text-slate-500">p50 {Math.round(row.latency.p50)} ms · p95 {Math.round(row.latency.p95)} ms</span>}
              </th>
              <td className={`${td} text-right font-mono text-amber-200`}>{row.thresholds?.suspicious_min_risk ?? '—'}</td>
              <td className={`${td} text-right font-mono text-red-200`}>{row.thresholds?.malicious_min_risk ?? '—'}</td>
              <td className={`${td} text-right font-mono`}>{pct(row.m.benign_fpr_flagged)}</td>
              <td className={`${td} text-right font-mono`}>{pct(row.m.benign_fpr_malicious)}</td>
              <td className={`${td} text-right font-mono`}>{pct(row.m.threat_recall_flagged)}</td>
              <td className={`${td} text-right font-mono`}>{pct(row.m.threat_recall_malicious)}</td>
              <td className={`${td} text-right font-mono`}>{pct(row.m.threat_class_accuracy)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function C2Research() {
  const { demo } = useDemoMode()
  const { data, error, loading, reload } = useAsyncData(
    async (signal) => (demo ? (await loadDemo()).research : getResearch({ signal })),
    String(demo),
  )
  if (!data && loading) return <StateBox state="loading" message="Loading the research summary…" />
  if (!data && error) return <StateBox state="error" message={error.message} onRetry={reload} />
  if (!data) return null

  const ablation = data.ablation
  const chartRows = (ablation?.rows || [])
    .filter((row) => row.selected_for_row && row.test_macro_f1 !== null)
    .map((row) => ({
      label: rowLabel(row),
      value: row.test_macro_f1,
      low: row.test_macro_f1_ci?.[0] ?? row.test_macro_f1,
      high: row.test_macro_f1_ci?.[1] ?? row.test_macro_f1,
      group: row.group,
      final: row.key === ablation.final?.key,
    }))

  return (
    <div className="flex flex-col gap-4">
      <h2 className="flex items-center gap-2 text-xl font-semibold text-slate-50">
        <FlaskConical className="h-5 w-5 text-cyan-300" aria-hidden="true" /> Research evidence
        <span className="font-mono text-sm font-normal text-slate-400">dataset {data.version} · read from C2's saved reports</span>
      </h2>
      {data.missing?.length > 0 && <p className="text-sm text-amber-300">Missing reports: {data.missing.join(', ')}</p>}

      <Panel title="How C2 works" icon={Network}>
        <ArchitectureDiagram />
      </Panel>

      <div className="grid gap-4 2xl:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
        <Panel title="Dataset composition" icon={Database}>
          {data.dataset ? <DatasetTable dataset={data.dataset} /> : <StateBox state="empty" message="No dataset manifest." />}
        </Panel>
        <Panel title="Ablation: does fusion help?" icon={BarChart3}>
          {chartRows.length ? <CiBarChart rows={chartRows} /> : <StateBox state="empty" message="No ablation report." />}
          <Comparison comparison={ablation?.comparison} />
        </Panel>
      </div>

      {ablation && (
        <Panel title="Ablation table (all rows)" icon={Boxes}>
          <AblationTable ablation={ablation} />
        </Panel>
      )}

      {data.operating_points && (
        <Panel title="Operating points (verdict tiers)" icon={Target}>
          <OperatingPoints points={data.operating_points} />
        </Panel>
      )}

      {data.models && (
        <Panel title="Model versions" icon={Boxes}>
          <ul className="grid gap-2 text-sm md:grid-cols-2 xl:grid-cols-4">
            {Object.entries(data.models.arms || {}).map(([arm, info]) => (
              <li key={arm} className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                <p className="font-semibold text-slate-100">{ARM_LABELS[arm] || arm}</p>
                <p className="text-xs text-slate-400">{info.part} · {info.model_display}</p>
                {info.seed !== undefined && <p className="font-mono text-xs text-slate-500">seed {info.seed} · {info.base_model}</p>}
                {info.model_trained_at && <p className="font-mono text-xs text-slate-500">trained {info.model_trained_at.slice(0, 10)}</p>}
              </li>
            ))}
          </ul>
          <p className="mt-2 text-xs text-slate-400">
            Fusion: {data.models.fusion?.strategy} · weights{' '}
            <span className="font-mono">
              {Object.entries(data.models.fusion?.weights || {}).map(([arm, weight]) => `${arm} ${weight}`).join(' · ')}
            </span>
          </p>
        </Panel>
      )}
    </div>
  )
}
