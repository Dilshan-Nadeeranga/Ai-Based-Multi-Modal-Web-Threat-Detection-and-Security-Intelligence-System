import { AlertTriangle, Brain, CloudOff, FileQuestion, Gauge, ListChecks, ShieldAlert } from 'lucide-react'
import { defangText } from '../api/defang.js'
import { CLASS_LABELS, LANGUAGE_LABELS, formatTime } from '../constants.js'
import FindingList from './FindingList.jsx'
import ModalityCard from './ModalityCard.jsx'
import { ArmContributions, ProbabilityBars } from './ProbabilityBars.jsx'
import RiskGauge from './RiskGauge.jsx'
import VerdictBadge from './VerdictBadge.jsx'
import { Chip, DefangedUrl, Panel } from './ui.jsx'

/** Unreachable / inconclusive / error are OUTCOMES, not crashes: designed calm states. */
function NoVerdictState({ result }) {
  const config = {
    unreachable: {
      icon: CloudOff,
      title: 'Page could not be reached — no verdict',
      text: 'C2 never guesses about a page it could not see. Scam pages are often taken down within hours, so "unreachable" is common for reported links. Try again later, or paste the page HTML if you have it.',
    },
    inconclusive: {
      icon: FileQuestion,
      title: 'Inconclusive — not enough of the real page to judge',
      text: 'The server answered with something that is not the page itself (bot challenge, parked domain, error or empty page, or not HTML). The evidence C2 did collect is listed below.',
    },
    error: {
      icon: AlertTriangle,
      title: result.partial ? 'Time budget exceeded — partial result' : 'Analysis error',
      text: 'C2 stopped before every step finished. The steps that did run are shown below.',
    },
  }[result.status]
  if (!config) return null
  const Icon = config.icon
  return (
    <div className="flex items-start gap-4 rounded-xl border border-slate-700 bg-slate-900/70 p-5">
      <span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-cyan-400/10 text-cyan-300 ring-1 ring-cyan-400/30">
        <Icon className="h-6 w-6" aria-hidden="true" />
      </span>
      <div className="min-w-0">
        <h3 className="text-lg font-semibold text-slate-50">{config.title}</h3>
        {result.status_reason && (
          <p className="mt-1 font-mono text-sm text-amber-200">{defangText(result.status_reason)}</p>
        )}
        <p className="mt-2 max-w-3xl text-sm text-slate-300">{config.text}</p>
      </div>
    </div>
  )
}

function Header({ result }) {
  const thresholds = result.explanation?.thresholds
  const floor = result.explanation?.evidence_floor_rules || []
  const language = result.page_language
  return (
    <div className="grid items-center gap-5 md:grid-cols-[auto_minmax(0,1fr)]">
      <RiskGauge score={result.risk_score} verdict={result.verdict} thresholds={result.verdict ? thresholds : null} />
      <div className="flex min-w-0 flex-col gap-3">
        <div className="flex flex-wrap items-center gap-3">
          <VerdictBadge verdict={result.verdict} size="lg" label={result.verdict ? null : `No verdict · ${result.status}`} />
          {result.threat_class && (
            <span className="text-lg font-semibold text-slate-100">
              {result.verdict === 'Legitimate' ? 'No threat class' : CLASS_LABELS[result.threat_class] || result.threat_class}
            </span>
          )}
        </div>
        <DefangedUrl url={result.input?.final_url || result.input?.submitted_url} />
        <div className="flex flex-wrap gap-2">
          <Chip tone="cyan">mode: {result.input?.mode}</Chip>
          {language && <Chip>language: {LANGUAGE_LABELS[language] || language}</Chip>}
          {result.input?.http_status && <Chip>HTTP {result.input.http_status}</Chip>}
          {result.input?.redirect_hosts?.length > 1 && <Chip tone="amber">{result.input.redirect_hosts.length - 1} redirect(s)</Chip>}
          {result.cached && <Chip>cached</Chip>}
          {result.degraded && (
            <Chip tone="amber" title="One modality failed; the other arms were fused with renormalized weights">
              degraded
            </Chip>
          )}
          {floor.length > 0 && (
            <Chip tone="red" title={floor.join(', ')}>
              <ShieldAlert className="h-3 w-3" aria-hidden="true" /> evidence floor: {floor.length} rule{floor.length > 1 ? 's' : ''}
            </Chip>
          )}
          {result.explanation?.verdict_source === 'evidence_floor' && <Chip tone="red">verdict raised by rule evidence</Chip>}
        </div>
        {floor.length > 0 && (
          <p className="text-xs text-slate-400">
            Rule evidence that a statistical model may not talk away:{' '}
            <span className="font-mono text-red-200">{floor.join(' · ')}</span>
          </p>
        )}
        {result.warnings?.length > 0 && (
          <ul className="flex flex-col gap-1">
            {result.warnings.map((warning, index) => (
              <li key={index} className="flex gap-2 rounded-md bg-amber-400/10 px-2 py-1 text-sm text-amber-100 ring-1 ring-amber-400/30">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" aria-hidden="true" />
                {defangText(warning)}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}

/** The full AnalysisResponse view, shared by Scan, Live feed and History. */
export default function ResultView({ result }) {
  if (!result) return null
  const noVerdict = !result.verdict
  const behaviorChain = (result.findings || []).find((finding) => finding.modality === 'behavior' && finding.steps?.length)?.steps
  const topFeatures = result.explanation?.top_features || []
  return (
    <div className="flex flex-col gap-4">
      <Panel title="Verdict" icon={Gauge}>
        <Header result={result} />
      </Panel>
      {noVerdict && <NoVerdictState result={result} />}

      <Panel title="Why? — findings by severity" icon={ListChecks}>
        <FindingList findings={result.findings} total={result.findings_total} omitted={result.findings_omitted} />
      </Panel>

      {result.status !== 'unreachable' && (
        <div className="grid gap-4 xl:grid-cols-3">
          <ModalityCard name="dom" modality={result.modalities?.dom} />
          <ModalityCard name="content" modality={result.modalities?.content} />
          <ModalityCard name="behavior" modality={result.modalities?.behavior} chain={behaviorChain} />
        </div>
      )}

      {Object.keys(result.class_probabilities || {}).length > 0 && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Panel title="Fused class probabilities" icon={Brain}>
            <ProbabilityBars probabilities={result.class_probabilities} highlight={result.explanation?.explained_class} />
          </Panel>
          <Panel title="Per-arm contribution" icon={Brain}>
            <ArmContributions explanation={result.explanation} modalities={result.modalities} />
            {topFeatures.length > 0 && (
              <details className="mt-3 text-sm">
                <summary className="cursor-pointer text-cyan-300 hover:text-cyan-100">Top input features ({topFeatures.length})</summary>
                <ul className="mt-2 flex flex-col gap-1 text-slate-300">
                  {topFeatures.slice(0, 8).map((feature, index) => (
                    <li key={index} className="font-mono text-xs">
                      <span className="text-slate-500">[{feature.arm}]</span> {defangText(feature.text)}
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </Panel>
        </div>
      )}

      <p className="font-mono text-[0.6875rem] text-slate-500">
        analysis {result.analysis_id} · {formatTime(result.analyzed_at)} · schema {result.schema_version}
        {result.model_versions?.fusion ? ` · fusion ${result.model_versions.fusion}` : ''}
      </p>
    </div>
  )
}
