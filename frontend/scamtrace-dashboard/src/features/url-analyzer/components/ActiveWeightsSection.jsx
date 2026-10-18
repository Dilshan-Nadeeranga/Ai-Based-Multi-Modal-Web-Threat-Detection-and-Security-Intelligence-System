import React, { useState } from 'react';
import {
  Sliders,
  RefreshCw,
  Info,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ArrowRight,
  Database,
  BrainCircuit,
  Network,
  Globe,
  Fingerprint,
  FileCode,
  Copy,
  ArrowRightLeft,
  Cpu,
  BarChart3,
  PieChart as PieIcon,
  ShieldCheck,
} from 'lucide-react';
import {
  SCORING_CHANNELS,
  ChannelWeightDonutChart,
  RenormalizationBarChart,
} from './AnalysisCharts.jsx';

const CHANNEL_ICONS = {
  domain_registration: Globe,
  lexical_structural: Fingerprint,
  dns_reputation: Network,
  machine_learning: BrainCircuit,
  entropy_obfuscation: FileCode,
  homoglyph_lookalike: Copy,
  shortener_redirect: ArrowRightLeft,
  dga: Cpu,
};

export default function ActiveWeightsSection({
  riskAssessment,
  nominalWeights = {},
  isDark = true,
  className = '',
}) {
  const [activeViewTab, setActiveViewTab] = useState('donut'); // 'donut' | 'bars'

  if (!riskAssessment) return null;

  const activeWeights = riskAssessment.active_weights || {};
  const channelScores = riskAssessment.channel_scores || {};
  const limitations = riskAssessment.analysis_limitations || [];

  // Calculate telemetry metrics
  let activeCount = 0;
  let excludedCount = 0;
  let totalEffectiveWeight = 0;
  let hasRenormalizationOccurred = false;

  SCORING_CHANNELS.forEach((ch) => {
    const nominal = nominalWeights[ch.key]?.weight !== undefined ? nominalWeights[ch.key].weight : ch.nominalWeight;
    const effective = activeWeights[ch.key] !== undefined ? activeWeights[ch.key] : ch.nominalWeight;

    if (effective > 0.001) {
      activeCount++;
      totalEffectiveWeight += effective;
    } else {
      excludedCount++;
    }

    if (Math.abs(effective - nominal) > 0.005) {
      hasRenormalizationOccurred = true;
    }
  });

  const totalEffectivePct = (totalEffectiveWeight * 100).toFixed(0);

  return (
    <section
      className={`rounded-2xl p-6 transition-all duration-200 c1-hover-card ${
        isDark
          ? 'bg-[#0b1329]/90 border border-cyan-500/30 shadow-[0_4px_30px_rgba(6,182,212,0.12)] text-slate-100'
          : 'bg-white border border-blue-500/30 shadow-[0_8px_30px_rgba(37,99,235,0.08)] text-slate-900 ring-1 ring-blue-500/10'
      } ${className}`}
    >
      {/* Section Header */}
      <div
        className={`flex flex-wrap items-center justify-between gap-4 border-b pb-5 ${
          isDark ? 'border-slate-800' : 'border-slate-200'
        }`}
      >
        <div className="flex items-start gap-3.5">
          <span
            className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border ${
              isDark
                ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30 shadow-[0_0_15px_rgba(6,182,212,0.2)]'
                : 'bg-blue-50 text-blue-600 border-blue-200 shadow-sm'
            }`}
          >
            <Sliders className="h-6 w-6" aria-hidden="true" />
          </span>
          <div>
            <div className="flex items-center gap-2">
              <span
                className={`text-[0.625rem] font-bold uppercase tracking-widest ${
                  isDark ? 'text-cyan-400' : 'text-blue-600'
                }`}
              >
                Core Research Contribution 3
              </span>
              <span
                className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[0.6875rem] font-semibold border ${
                  isDark
                    ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30'
                    : 'bg-blue-50 text-blue-700 border-blue-200'
                }`}
              >
                <RefreshCw className={`h-3 w-3 animate-spin ${isDark ? 'text-cyan-400' : 'text-blue-600'}`} />
                Availability-Aware Dynamic Renormalization
              </span>
            </div>
            <h3
              className={`font-manrope text-xl font-bold tracking-tight mt-0.5 ${
                isDark ? 'text-white' : 'text-slate-900'
              }`}
            >
              Active Channel Weights & Dynamic Renormalization
            </h3>
            <p className={`text-xs mt-1 max-w-3xl leading-relaxed ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
              When telemetry channels (such as WHOIS/RDAP, DNS, or Threat Feeds) are unavailable or inapplicable (e.g. direct IP URLs),
              they are cleanly excluded, and the remaining active channel weights are dynamically renormalized to sum to 1.0 (100%).
            </p>
          </div>
        </div>

        {/* View Switcher Pills */}
        <div
          className={`flex items-center rounded-lg p-1 border text-xs ${
            isDark ? 'bg-slate-950 border-slate-800' : 'bg-slate-100 border-slate-200'
          }`}
        >
          <button
            type="button"
            onClick={() => setActiveViewTab('donut')}
            className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 font-medium transition cursor-pointer ${
              activeViewTab === 'donut'
                ? isDark
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-xs'
                  : 'bg-white text-blue-700 border border-blue-200 shadow-xs'
                : isDark
                ? 'text-slate-400 hover:text-white'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <PieIcon className="h-3.5 w-3.5" />
            <span>Weight Donut</span>
          </button>
          <button
            type="button"
            onClick={() => setActiveViewTab('bars')}
            className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 font-medium transition cursor-pointer ${
              activeViewTab === 'bars'
                ? isDark
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-xs'
                  : 'bg-white text-blue-700 border border-blue-200 shadow-xs'
                : isDark
                ? 'text-slate-400 hover:text-white'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <BarChart3 className="h-3.5 w-3.5" />
            <span>Configured vs Effective</span>
          </button>
        </div>
      </div>

      {/* D. Weight Summary KPIs Strip */}
      <div className="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
        {/* KPI 1: Active Channels */}
        <div
          className={`rounded-xl p-3.5 border c1-kpi-card ${
            isDark ? 'bg-slate-950/80 border-slate-800/80' : 'bg-slate-50 border-slate-200 shadow-2xs'
          }`}
        >
          <div className={`text-[0.625rem] font-bold uppercase tracking-wider ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
            Active Channels
          </div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className={`font-mono text-2xl font-extrabold ${isDark ? 'text-white' : 'text-slate-900'}`}>{activeCount}</span>
            <span className={`text-xs font-mono ${isDark ? 'text-slate-500' : 'text-slate-400'}`}>/ 8 Channels</span>
          </div>
          <p className="mt-1 text-[0.6875rem] text-emerald-600 dark:text-emerald-400 flex items-center gap-1 font-medium">
            <CheckCircle2 className="h-3 w-3" /> Fused into final score
          </p>
        </div>

        {/* KPI 2: Excluded Channels */}
        <div
          className={`rounded-xl p-3.5 border c1-kpi-card ${
            isDark ? 'bg-slate-950/80 border-slate-800/80' : 'bg-slate-50 border-slate-200 shadow-2xs'
          }`}
        >
          <div className={`text-[0.625rem] font-bold uppercase tracking-wider ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
            Excluded Channels
          </div>
          <div className="mt-1 flex items-baseline gap-2">
            <span
              className={`font-mono text-2xl font-extrabold ${
                excludedCount > 0 ? (isDark ? 'text-amber-400' : 'text-amber-600') : (isDark ? 'text-slate-400' : 'text-slate-600')
              }`}
            >
              {excludedCount}
            </span>
            <span className={`text-xs font-mono ${isDark ? 'text-slate-500' : 'text-slate-400'}`}>Missing / Inapplicable</span>
          </div>
          <p className={`mt-1 text-[0.6875rem] ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
            {excludedCount > 0 ? 'Zero-weighted & redistributed' : 'All channels observable'}
          </p>
        </div>

        {/* KPI 3: Total Effective Weight */}
        <div
          className={`rounded-xl p-3.5 border c1-kpi-card ${
            isDark ? 'bg-slate-950/80 border-slate-800/80' : 'bg-slate-50 border-slate-200 shadow-2xs'
          }`}
        >
          <div className={`text-[0.625rem] font-bold uppercase tracking-wider ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
            Total Effective Weight
          </div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className={`font-mono text-2xl font-extrabold ${isDark ? 'text-cyan-400' : 'text-blue-600'}`}>{totalEffectivePct}%</span>
            <span className={`text-xs font-mono ${isDark ? 'text-slate-500' : 'text-slate-400'}`}>Σ w_i = 1.0</span>
          </div>
          <p className={`mt-1 text-[0.6875rem] font-medium ${isDark ? 'text-cyan-300/80' : 'text-blue-700'}`}>Strict Mathematical Parity</p>
        </div>

        {/* KPI 4: Renormalization Status */}
        <div
          className={`rounded-xl p-3.5 border c1-kpi-card ${
            isDark ? 'bg-slate-950/80 border-slate-800/80' : 'bg-slate-50 border-slate-200 shadow-2xs'
          }`}
        >
          <div className={`text-[0.625rem] font-bold uppercase tracking-wider ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
            Dynamic State
          </div>
          <div className="mt-1 flex items-baseline gap-2">
            <span className={`font-mono text-lg font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>
              {hasRenormalizationOccurred ? 'Renormalized' : 'Nominal Baseline'}
            </span>
          </div>
          <p className={`mt-1 text-[0.6875rem] ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
            {hasRenormalizationOccurred ? 'Weights scaled up dynamically' : 'Standard 8-channel baseline'}
          </p>
        </div>
      </div>

      {/* Main Visualizations: Chart 1 (Donut) OR Chart 2 (Grouped Bar Comparison) */}
      <div
        className={`mt-6 rounded-xl p-5 border ${
          isDark ? 'bg-slate-950/90 border-slate-800' : 'bg-slate-50/70 border-slate-200 shadow-xs'
        }`}
      >
        {activeViewTab === 'donut' ? (
          <div>
            <div className={`mb-4 flex items-center justify-between border-b pb-3 ${isDark ? 'border-slate-800/80' : 'border-slate-200'}`}>
              <div>
                <h4 className={`font-manrope text-sm font-bold flex items-center gap-2 ${isDark ? 'text-white' : 'text-slate-900'}`}>
                  <PieIcon className={`h-4 w-4 ${isDark ? 'text-cyan-400' : 'text-blue-600'}`} />
                  Chart 1 — Active Channel Weight Distribution
                </h4>
                <p className={`text-xs mt-0.5 ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
                  Relative contribution of active channels currently fused into the composite risk score.
                </p>
              </div>
              <span className={`text-[0.6875rem] font-mono ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
                Interactive: Hover slice for telemetry
              </span>
            </div>
            <ChannelWeightDonutChart activeWeights={activeWeights} nominalWeights={nominalWeights} isDark={isDark} />
          </div>
        ) : (
          <div>
            <div className={`mb-4 flex items-center justify-between border-b pb-3 ${isDark ? 'border-slate-800/80' : 'border-slate-200'}`}>
              <div>
                <h4 className={`font-manrope text-sm font-bold flex items-center gap-2 ${isDark ? 'text-white' : 'text-slate-900'}`}>
                  <BarChart3 className={`h-4 w-4 ${isDark ? 'text-cyan-400' : 'text-blue-600'}`} />
                  Chart 2 — Configured vs Effective Dynamic Renormalization
                </h4>
                <p className={`text-xs mt-0.5 ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
                  Direct comparison between initial configured nominal weights and the adjusted effective weights after missing channels are excluded.
                </p>
              </div>
              <span className={`text-[0.6875rem] font-mono font-bold ${isDark ? 'text-cyan-400' : 'text-blue-600'}`}>
                W_eff = W_nom / Σ(W_avail)
              </span>
            </div>
            <RenormalizationBarChart activeWeights={activeWeights} nominalWeights={nominalWeights} isDark={isDark} />
          </div>
        )}
      </div>

      {/* Dynamic Renormalization Mathematical Explanation */}
      <div
        className={`mt-5 rounded-xl p-4 border flex items-start gap-3.5 ${
          isDark
            ? 'bg-cyan-950/20 border-cyan-500/30 text-slate-300'
            : 'bg-blue-50/80 border-blue-200 text-slate-700'
        }`}
      >
        <Info className={`h-5 w-5 shrink-0 mt-0.5 ${isDark ? 'text-cyan-400' : 'text-blue-600'}`} />
        <div className="text-xs leading-relaxed">
          <strong className={`font-semibold ${isDark ? 'text-cyan-300' : 'text-blue-800'}`}>
            Dynamic Renormalization In Action:{' '}
          </strong>
          Unavailable channels are excluded from the active calculation, and the remaining weights are renormalized according to the backend's scoring logic:
          <span
            className={`font-mono font-bold px-2 py-0.5 rounded mx-1.5 border ${
              isDark
                ? 'text-cyan-200 bg-slate-900 border-cyan-800'
                : 'text-blue-800 bg-white border-blue-300 shadow-2xs'
            }`}
          >
            W_active = W_nominal / Σ(W_available)
          </span>
          This prevents false negatives from penalizing missing metadata and guarantees that absent WHOIS or DNS feeds never artificially lower or spike a domain's threat score.
        </div>
      </div>

      {/* C. Channel Availability Cards (8 Channels Grid) */}
      <div className="mt-6">
        <div className="mb-3 flex items-center justify-between">
          <h4 className={`font-manrope text-sm font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>
            Individual Scoring Channel Telemetry & Status
          </h4>
          <span className={`text-[0.6875rem] ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
            8 Total Channels Configured in Engine v{riskAssessment.engine_version}
          </span>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {SCORING_CHANNELS.map((ch) => {
            const Icon = CHANNEL_ICONS[ch.key] || Sliders;
            const nominal = (nominalWeights[ch.key]?.weight !== undefined ? nominalWeights[ch.key].weight : ch.nominalWeight) * 100;
            const effective = (activeWeights[ch.key] !== undefined ? activeWeights[ch.key] : ch.nominalWeight) * 100;
            const isAvailable = effective > 0.01;
            const rawScore = channelScores[ch.key] || 0.0;
            const points = (rawScore * (effective / 100)).toFixed(1);

            return (
              <div
                key={ch.key}
                className={`flex flex-col justify-between rounded-xl p-3.5 border transition-all c1-kpi-card ${
                  isAvailable
                    ? isDark
                      ? 'bg-slate-950/70 border-slate-800 hover:border-slate-700 hover:bg-slate-950'
                      : 'bg-white border-slate-200 hover:border-slate-300 hover:bg-slate-50/80 shadow-xs'
                    : isDark
                    ? 'bg-slate-950/30 border-dashed border-amber-900/40 opacity-75'
                    : 'bg-slate-50 border-dashed border-amber-300/80 opacity-75'
                }`}
              >
                <div>
                  {/* Card Header */}
                  <div className="flex items-center justify-between">
                    <span
                      className="flex h-7 w-7 items-center justify-center rounded-lg"
                      style={{ backgroundColor: ch.bgMuted, color: ch.color }}
                    >
                      <Icon className="h-4 w-4" />
                    </span>
                    {isAvailable ? (
                      <span className="inline-flex items-center gap-1 rounded bg-emerald-500/15 px-2 py-0.5 text-[0.625rem] font-bold text-emerald-600 dark:text-emerald-400 border border-emerald-500/30">
                        <CheckCircle2 className="h-3 w-3" /> ACTIVE
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 rounded bg-amber-500/15 px-2 py-0.5 text-[0.625rem] font-bold text-amber-700 dark:text-amber-400 border border-amber-500/30">
                        <XCircle className="h-3 w-3" /> EXCLUDED
                      </span>
                    )}
                  </div>

                  {/* Title & Description */}
                  <h5
                    className={`font-semibold text-xs mt-2 line-clamp-1 ${
                      isDark ? 'text-white' : 'text-slate-900'
                    }`}
                    title={ch.name}
                  >
                    {ch.name}
                  </h5>
                  <p className={`text-[0.6875rem] mt-1 line-clamp-2 leading-relaxed ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
                    {ch.description}
                  </p>
                </div>

                {/* Footer Weights & Sub-score */}
                <div
                  className={`mt-3 pt-2.5 border-t space-y-1 text-[0.6875rem] font-mono ${
                    isDark ? 'border-slate-800/80' : 'border-slate-100'
                  }`}
                >
                  <div className={`flex justify-between ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
                    <span>Configured:</span>
                    <span>{nominal.toFixed(1)}%</span>
                  </div>
                  <div className="flex justify-between">
                    <span className={isDark ? 'text-slate-400' : 'text-slate-500'}>Effective:</span>
                    <span className={`font-bold ${
                      isAvailable
                        ? isDark ? 'text-cyan-300' : 'text-blue-700'
                        : isDark ? 'text-slate-500' : 'text-slate-400'
                    }`}>
                      {effective.toFixed(1)}%
                    </span>
                  </div>
                  <div
                    className={`flex justify-between pt-1 border-t ${
                      isDark ? 'text-slate-400 border-slate-900' : 'text-slate-600 border-slate-100'
                    }`}
                  >
                    <span>Score Impact:</span>
                    <span className={`font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>+{points} pts</span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Explicit Missing Limitations Notice (if any) */}
      {limitations.length > 0 && (
        <div
          className={`mt-5 rounded-xl p-3.5 border ${
            isDark
              ? 'bg-amber-950/20 border-amber-500/30'
              : 'bg-amber-50 border-amber-200'
          }`}
        >
          <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-amber-600 dark:text-amber-400">
            <AlertTriangle className="h-4 w-4" /> Evaluated Limitations & Missing Telemetry
          </div>
          <ul className={`mt-2 space-y-1 text-xs ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
            {limitations.map((lim, idx) => (
              <li key={idx} className="flex items-start gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-amber-500 mt-1.5 shrink-0" />
                <span>{lim}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
