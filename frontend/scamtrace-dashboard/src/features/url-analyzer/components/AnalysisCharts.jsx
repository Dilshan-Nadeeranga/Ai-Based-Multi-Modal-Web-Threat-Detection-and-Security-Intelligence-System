import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Layers,
  ArrowRight,
  TrendingUp,
  Activity,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Zap,
} from 'lucide-react';

// Channel definitions with calibrated nominal weights and SOC cyber color palette
export const SCORING_CHANNELS = [
  {
    key: 'domain_registration',
    name: 'WHOIS & Registration Age',
    shortName: 'WHOIS / Reg',
    nominalWeight: 0.20,
    color: '#3b82f6', // Cobalt Blue
    bgMuted: 'rgba(59, 130, 246, 0.15)',
    description: 'Evaluates domain registration age, NRD threshold (<= 30d), and registrar validity.',
  },
  {
    key: 'lexical_structural',
    name: 'URL Lexical & Path Syntax',
    shortName: 'URL Syntax',
    nominalWeight: 0.15,
    color: '#06b6d4', // Cyan
    bgMuted: 'rgba(6, 182, 212, 0.15)',
    description: 'Analyzes path depth, suspicious keywords, special delimiters, and structural ratios.',
  },
  {
    key: 'dns_reputation',
    name: 'DNS Infrastructure & Feeds',
    shortName: 'DNS / Feeds',
    nominalWeight: 0.15,
    color: '#6366f1', // Indigo
    bgMuted: 'rgba(99, 102, 241, 0.15)',
    description: 'Flags fast-flux turnover, private RFC-1918 resolution, and threat intelligence feeds.',
  },
  {
    key: 'machine_learning',
    name: 'Supervised ML Classifier (RF)',
    shortName: 'ML Model (RF)',
    nominalWeight: 0.15,
    color: '#10b981', // Emerald
    bgMuted: 'rgba(16, 185, 129, 0.15)',
    description: 'Non-linear pattern recognition over a 57-dimensional lexical and structural vector.',
  },
  {
    key: 'entropy_obfuscation',
    name: 'Entropy & Evasion Obfuscation',
    shortName: 'Entropy / Obf',
    nominalWeight: 0.10,
    color: '#14b8a6', // Teal
    bgMuted: 'rgba(20, 184, 166, 0.15)',
    description: 'Measures Shannon entropy, percent-encoding evasion, authority @ masking, and hex IPs.',
  },
  {
    key: 'homoglyph_lookalike',
    name: 'Homoglyph & Brand Lookalike',
    shortName: 'Homoglyphs',
    nominalWeight: 0.10,
    color: '#38bdf8', // Sky Blue
    bgMuted: 'rgba(56, 189, 248, 0.15)',
    description: 'Detects Cyrillic/Latin confusable scripts and Punycode spoofing targeting brands.',
  },
  {
    key: 'shortener_redirect',
    name: 'Shortener & Safe Redirect Tracing',
    shortName: 'Redirects',
    nominalWeight: 0.10,
    color: '#f59e0b', // Amber
    bgMuted: 'rgba(245, 158, 11, 0.15)',
    description: 'Traces cross-domain hops, cyclic loops, and blocks private SSRF target destinations.',
  },
  {
    key: 'dga',
    name: 'Algorithmic DGA Detection',
    shortName: 'DGA Engine',
    nominalWeight: 0.05,
    color: '#a855f7', // Purple
    bgMuted: 'rgba(168, 85, 247, 0.15)',
    description: 'Measures domain randomness, consonant clustering, and bigram transition perplexity.',
  },
];

// Polar to cartesian helper for SVG arc paths
function polarToCartesian(centerX, centerY, radius, angleInDegrees) {
  const angleInRadians = ((angleInDegrees - 90) * Math.PI) / 180.0;
  return {
    x: centerX + radius * Math.cos(angleInRadians),
    y: centerY + radius * Math.sin(angleInRadians),
  };
}

function describeDonutSlice(x, y, radiusInner, radiusOuter, startAngle, endAngle) {
  // Ensure valid angle span (avoid 360-degree SVG arc collision)
  const angleSpan = endAngle - startAngle;
  const clampedEnd = angleSpan >= 359.99 ? startAngle + 359.99 : endAngle;

  const startOuter = polarToCartesian(x, y, radiusOuter, clampedEnd);
  const endOuter = polarToCartesian(x, y, radiusOuter, startAngle);
  const startInner = polarToCartesian(x, y, radiusInner, startAngle);
  const endInner = polarToCartesian(x, y, radiusInner, clampedEnd);

  const arcSweep = angleSpan <= 180 ? '0' : '1';

  return [
    'M', startOuter.x, startOuter.y,
    'A', radiusOuter, radiusOuter, 0, arcSweep, 0, endOuter.x, endOuter.y,
    'L', startInner.x, startInner.y,
    'A', radiusInner, radiusInner, 0, arcSweep, 1, endInner.x, endInner.y,
    'Z'
  ].join(' ');
}

// ---------------------------------------------------------------------------
// 1. Chart 1 — Active Channel Weight Donut Chart
// ---------------------------------------------------------------------------
export function ChannelWeightDonutChart({ activeWeights = {}, nominalWeights = {}, isDark = true }) {
  const [hoveredChannel, setHoveredChannel] = useState(null);

  // Compute active channels with positive weight
  const slices = [];
  let cumulativeAngle = 0;

  SCORING_CHANNELS.forEach((ch) => {
    const effWeight = activeWeights[ch.key] !== undefined ? activeWeights[ch.key] : ch.nominalWeight;
    const isAvailable = effWeight > 0.001;
    const weightPct = effWeight * 100;

    if (isAvailable) {
      const sliceAngle = effWeight * 360;
      const startAngle = cumulativeAngle;
      const endAngle = cumulativeAngle + sliceAngle;
      cumulativeAngle = endAngle;

      slices.push({
        ...ch,
        effectiveWeight: effWeight,
        weightPct,
        startAngle,
        endAngle,
      });
    }
  });

  const activeCount = slices.length;
  const totalWeightPct = slices.reduce((acc, s) => acc + s.weightPct, 0).toFixed(0);

  return (
    <div className="flex flex-col items-center gap-6 lg:flex-row lg:items-center">
      {/* Donut SVG Visual */}
      <div className="relative flex shrink-0 items-center justify-center">
        <svg
          viewBox="0 0 280 280"
          className="h-64 w-64 drop-shadow-[0_4px_20px_rgba(0,0,0,0.3)]"
          aria-label="Active channel weights donut chart"
        >
          {/* Subtle Outer Track Glow */}
          <circle
            cx="140"
            cy="140"
            r="112"
            fill="none"
            stroke={isDark ? '#1e293b' : '#e2e8f0'}
            strokeWidth="1.5"
            className="opacity-70"
          />

          {/* Slices */}
          {slices.map((slice) => {
            const isHovered = hoveredChannel?.key === slice.key;
            const outerR = isHovered ? 124 : 118;
            const innerR = 76;
            const pathD = describeDonutSlice(140, 140, innerR, outerR, slice.startAngle, slice.endAngle);

            return (
              <path
                key={slice.key}
                d={pathD}
                fill={slice.color}
                fillOpacity={isHovered ? 1.0 : 0.88}
                stroke={isDark ? '#080e1e' : '#ffffff'}
                strokeWidth="2.5"
                className="cursor-pointer transition-all duration-200 hover:brightness-125"
                onMouseEnter={() => setHoveredChannel(slice)}
                onMouseLeave={() => setHoveredChannel(null)}
              />
            );
          })}

          {/* Center Hole Background */}
          <circle
            cx="140"
            cy="140"
            r="74"
            fill={isDark ? '#080e1e' : '#ffffff'}
            stroke={isDark ? '#1e293b' : '#cbd5e1'}
            strokeWidth="1.5"
          />
        </svg>

        {/* Center Interactive Typography */}
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center text-center px-4">
          {hoveredChannel ? (
            <div className="animate-in fade-in zoom-in-95 duration-150">
              <span className={`text-[0.625rem] font-bold uppercase tracking-wider ${isDark ? 'text-cyan-400' : 'text-blue-600'}`}>
                {hoveredChannel.shortName}
              </span>
              <div className={`font-mono text-2xl font-extrabold ${isDark ? 'text-white' : 'text-slate-900'}`}>
                {hoveredChannel.weightPct.toFixed(1)}%
              </div>
              <span className={`text-[0.625rem] font-medium ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Active Weight</span>
            </div>
          ) : (
            <div>
              <span className={`text-[0.625rem] font-bold uppercase tracking-widest ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
                Total Fused
              </span>
              <div className={`font-mono text-3xl font-extrabold tracking-tight ${isDark ? 'text-white' : 'text-slate-900'}`}>
                {totalWeightPct}%
              </div>
              <span className={`inline-flex items-center gap-1 text-[0.625rem] font-medium ${isDark ? 'text-cyan-300' : 'text-blue-700 font-semibold'}`}>
                <span className={`h-1.5 w-1.5 rounded-full animate-pulse ${isDark ? 'bg-cyan-400' : 'bg-blue-600'}`} />
                {activeCount} Active Channels
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Legend & Channel Roster */}
      <div className="grid flex-1 grid-cols-1 gap-2 sm:grid-cols-2">
        {SCORING_CHANNELS.map((ch) => {
          const effWeight = activeWeights[ch.key] !== undefined ? activeWeights[ch.key] : ch.nominalWeight;
          const isAvailable = effWeight > 0.001;
          const weightPct = (effWeight * 100).toFixed(1);
          const isHovered = hoveredChannel?.key === ch.key;

          return (
            <div
              key={ch.key}
              onMouseEnter={() => isAvailable && setHoveredChannel({ ...ch, weightPct: effWeight * 100 })}
              onMouseLeave={() => setHoveredChannel(null)}
              className={`flex items-center justify-between rounded-lg px-3 py-2 text-xs transition-all ${
                isHovered
                  ? isDark
                    ? 'bg-slate-800/90 ring-1 ring-cyan-500/60 shadow-lg'
                    : 'bg-blue-50 ring-1 ring-blue-500/50 shadow-md'
                  : isDark
                  ? 'bg-slate-900/60 hover:bg-slate-800/50 border border-slate-800/80'
                  : 'bg-slate-50 hover:bg-slate-100/90 border border-slate-200'
              }`}
            >
              <div className="flex items-center gap-2.5 truncate">
                <span
                  className="h-2.5 w-2.5 shrink-0 rounded-sm"
                  style={{ backgroundColor: isAvailable ? ch.color : isDark ? '#475569' : '#94a3b8' }}
                />
                <span
                  className={`truncate font-medium ${
                    isAvailable
                      ? isDark ? 'text-slate-200' : 'text-slate-800'
                      : isDark ? 'text-slate-500 line-through' : 'text-slate-400 line-through'
                  }`}
                >
                  {ch.name}
                </span>
              </div>
              <div className="ml-2 flex items-center gap-1.5 font-mono">
                {isAvailable ? (
                  <span className={`font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>{weightPct}%</span>
                ) : (
                  <span className={`rounded px-1.5 py-0.5 text-[0.625rem] font-semibold ${
                    isDark ? 'bg-slate-800 text-amber-400' : 'bg-amber-100 text-amber-800 border border-amber-200'
                  }`}>
                    EXCLUDED
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// 2. Chart 2 — Configured vs Effective Dynamically Renormalized Weights
// ---------------------------------------------------------------------------
export function RenormalizationBarChart({ activeWeights = {}, nominalWeights = {}, isDark = true }) {
  return (
    <div className="space-y-3.5">
      {/* Legend Header */}
      <div className={`flex items-center justify-end gap-5 text-xs pb-1 ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
        <div className="flex items-center gap-2">
          <span className={`h-2.5 w-4 rounded-sm ${isDark ? 'bg-slate-600' : 'bg-slate-400'}`} />
          <span>Configured Nominal (Prior)</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="h-2.5 w-4 rounded-sm bg-gradient-to-r from-cyan-500 to-blue-500 shadow-sm" />
          <span className={`font-semibold ${isDark ? 'text-cyan-300' : 'text-blue-700'}`}>Effective (Dynamic Renormalized)</span>
        </div>
      </div>

      {SCORING_CHANNELS.map((ch) => {
        const nominal = (nominalWeights[ch.key]?.weight !== undefined ? nominalWeights[ch.key].weight : ch.nominalWeight) * 100;
        const effectiveRaw = activeWeights[ch.key] !== undefined ? activeWeights[ch.key] : ch.nominalWeight;
        const effective = effectiveRaw * 100;
        const isExcluded = effective <= 0.01;
        const delta = effective - nominal;
        const maxScale = 35; // Maximum percentage scale for visual normalization

        return (
          <div
            key={ch.key}
            className={`group rounded-lg p-2.5 transition ${
              isDark
                ? 'bg-slate-900/60 border border-slate-800/80 hover:border-slate-700'
                : 'bg-white border border-slate-200 hover:border-slate-300 shadow-xs'
            }`}
          >
            {/* Row Header */}
            <div className="flex items-center justify-between text-xs mb-1.5">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full" style={{ backgroundColor: ch.color }} />
                <span className={`font-semibold ${isDark ? 'text-slate-200' : 'text-slate-800'}`}>{ch.name}</span>
              </div>
              <div className="flex items-center gap-2 font-mono">
                {isExcluded ? (
                  <span className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-[0.625rem] font-bold ${
                    isDark
                      ? 'bg-amber-500/10 text-amber-400 ring-1 ring-amber-500/30'
                      : 'bg-amber-50 text-amber-800 ring-1 ring-amber-300'
                  }`}>
                    <XCircle className="h-3 w-3" /> Excluded (0.0%)
                  </span>
                ) : (
                  <>
                    <span className={`text-[0.6875rem] ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>Nom: {nominal.toFixed(1)}%</span>
                    <ArrowRight className={`h-3 w-3 ${isDark ? 'text-slate-500' : 'text-slate-400'}`} />
                    <span className={`font-bold ${isDark ? 'text-cyan-300' : 'text-blue-700'}`}>{effective.toFixed(1)}%</span>
                    {delta !== 0 && (
                      <span className={`text-[0.625rem] font-bold px-1.5 py-0.2 rounded ${
                        delta > 0
                          ? isDark ? 'bg-cyan-500/20 text-cyan-300' : 'bg-blue-100 text-blue-800'
                          : isDark ? 'bg-rose-500/20 text-rose-300' : 'bg-rose-100 text-rose-800'
                      }`}>
                        {delta > 0 ? `+${delta.toFixed(1)}%` : `${delta.toFixed(1)}%`}
                      </span>
                    )}
                  </>
                )}
              </div>
            </div>

            {/* Grouped Bars */}
            <div className="space-y-1">
              {/* Nominal Bar */}
              <div className={`h-2 w-full overflow-hidden rounded-full ${isDark ? 'bg-slate-800/80' : 'bg-slate-200'}`}>
                <div
                  className={`h-full rounded-full transition-all duration-700 ${isDark ? 'bg-slate-600' : 'bg-slate-400'}`}
                  style={{ width: `${Math.min((nominal / maxScale) * 100, 100)}%` }}
                  title={`Configured Nominal: ${nominal.toFixed(1)}%`}
                />
              </div>

              {/* Effective Renormalized Bar */}
              <div className={`h-2.5 w-full overflow-hidden rounded-full ${isDark ? 'bg-slate-800/80' : 'bg-slate-200'}`}>
                {isExcluded ? (
                  <div className={`h-full w-full bg-repeating-linear-stripes ${isDark ? 'opacity-40' : 'opacity-20'}`} />
                ) : (
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-600 shadow-[0_0_8px_rgba(6,182,212,0.3)] transition-all duration-700"
                    style={{ width: `${Math.min((effective / maxScale) * 100, 100)}%` }}
                    title={`Effective Dynamically Renormalized: ${effective.toFixed(1)}%`}
                  />
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// 3. Chart 3 — Risk Score Breakdown by Contributing Channel
// ---------------------------------------------------------------------------
export function RiskScoreBreakdownChart({ channelScores = {}, activeWeights = {}, finalScore = 0, isDark = true }) {
  const contributions = SCORING_CHANNELS.map((ch) => {
    const rawScore = channelScores[ch.key] || 0.0;
    const effWeight = activeWeights[ch.key] !== undefined ? activeWeights[ch.key] : ch.nominalWeight;
    const points = rawScore * effWeight;
    return {
      ...ch,
      rawScore,
      effWeight,
      points,
    };
  }).filter((c) => c.effWeight > 0.001);

  return (
    <div className="space-y-3">
      <div className={`flex items-center justify-between text-xs pb-1 ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
        <span>Channel Sub-Score & Evaluated Points</span>
        <span className="font-mono">
          Total Risk Score: <strong className={`font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>{finalScore} / 100</strong>
        </span>
      </div>

      {contributions.map((ch) => {
        return (
          <div
            key={ch.key}
            className={`rounded-lg p-3 space-y-1.5 ${
              isDark
                ? 'bg-slate-900/60 border border-slate-800/80'
                : 'bg-white border border-slate-200 shadow-xs'
            }`}
          >
            <div className="flex items-center justify-between text-xs">
              <span className={`font-semibold ${isDark ? 'text-slate-200' : 'text-slate-800'}`}>{ch.name}</span>
              <div className="flex items-center gap-3 font-mono text-xs">
                <span className={isDark ? 'text-slate-400' : 'text-slate-500'}>
                  Sub-Score: <strong className={isDark ? 'text-slate-200' : 'text-slate-800'}>{ch.rawScore.toFixed(1)}</strong>
                </span>
                <span className={isDark ? 'text-slate-500' : 'text-slate-400'}>×</span>
                <span className={isDark ? 'text-slate-400' : 'text-slate-500'}>
                  W: <strong className={isDark ? 'text-cyan-300' : 'text-blue-700'}>{(ch.effWeight * 100).toFixed(0)}%</strong>
                </span>
                <span className={isDark ? 'text-slate-500' : 'text-slate-400'}>=</span>
                <span className={`font-bold px-2 py-0.5 rounded border ${
                  isDark ? 'bg-slate-800 border-slate-700 text-white' : 'bg-slate-100 border-slate-200 text-slate-900'
                }`}>
                  +{ch.points.toFixed(1)} pts
                </span>
              </div>
            </div>

            {/* Score Bar with Sub-score Fill */}
            <div className={`h-2 w-full overflow-hidden rounded-full ${isDark ? 'bg-slate-800' : 'bg-slate-200'}`}>
              <div
                className={`h-full transition-all duration-700 ${
                  ch.rawScore >= 60 ? 'bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.4)]' :
                  ch.rawScore >= 25 ? 'bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.4)]' :
                  'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.3)]'
                }`}
                style={{ width: `${Math.min(ch.rawScore, 100)}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// 4. Radial Score Gauge
// ---------------------------------------------------------------------------
export function RadialScoreGauge({ score = 0, verdict = 'SAFE', isDark = true }) {
  const clampedScore = Math.min(Math.max(score, 0), 100);

  // Colors based on verdict / score
  const isDanger = verdict === 'MALICIOUS' || verdict === 'PHISHING' || clampedScore >= 60;
  const isWarn = verdict === 'SUSPICIOUS' || clampedScore >= 25;

  const strokeColor = isDanger ? '#ef4444' : isWarn ? '#f59e0b' : '#10b981';
  const glowColor = isDanger ? 'rgba(239, 68, 68, 0.35)' : isWarn ? 'rgba(245, 158, 11, 0.35)' : 'rgba(16, 185, 129, 0.35)';

  // 240 degree gauge arc calculation
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const arcLength = circumference * (240 / 360);
  const strokeDashoffset = arcLength - (clampedScore / 100) * arcLength;

  return (
    <div className="relative flex flex-col items-center justify-center p-2">
      <svg
        viewBox="0 0 180 180"
        className="h-44 w-44 drop-shadow-[0_4px_16px_rgba(0,0,0,0.3)] -rotate-120"
      >
        {/* Gauge Background Track */}
        <circle
          cx="90"
          cy="90"
          r={radius}
          fill="none"
          stroke={isDark ? '#1e293b' : '#e2e8f0'}
          strokeWidth="12"
          strokeDasharray={`${arcLength} ${circumference}`}
          strokeLinecap="round"
        />

        {/* Dynamic Progress Arc */}
        <circle
          cx="90"
          cy="90"
          r={radius}
          fill="none"
          stroke={strokeColor}
          strokeWidth="12"
          strokeDasharray={`${arcLength} ${circumference}`}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          className="transition-all duration-1000 ease-out"
          style={{ filter: `drop-shadow(0 0 8px ${glowColor})` }}
        />
      </svg>

      {/* Center Score Readout */}
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
        <span className={`text-[0.625rem] font-bold uppercase tracking-widest ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
          Composite Risk
        </span>
        <div className={`font-mono text-4xl font-extrabold tracking-tight mt-0.5 ${isDark ? 'text-white' : 'text-slate-900'}`}>
          {clampedScore}
          <span className={`text-sm font-normal ml-0.5 ${isDark ? 'text-slate-500' : 'text-slate-400'}`}>/100</span>
        </div>
        <div className="mt-1">
          <span
            className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[0.6875rem] font-bold tracking-wide uppercase ${
              isDanger
                ? isDark ? 'bg-rose-500/20 text-rose-300 ring-1 ring-rose-500/40' : 'bg-rose-100 text-rose-800 ring-1 ring-rose-300'
                : isWarn
                ? isDark ? 'bg-amber-500/20 text-amber-300 ring-1 ring-amber-500/40' : 'bg-amber-100 text-amber-800 ring-1 ring-amber-300'
                : isDark ? 'bg-emerald-500/20 text-emerald-300 ring-1 ring-emerald-500/40' : 'bg-emerald-100 text-emerald-800 ring-1 ring-emerald-300'
            }`}
          >
            {verdict}
          </span>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// 5. Chart 4 — Analysis Layer Status Tracker Pipeline
// ---------------------------------------------------------------------------
export function LayerStatusPipeline({ result, isDark = true, activeTab, onSelectTab }) {
  if (!result) return null;

  const features = result.features;
  const domain = result.domain_intelligence;
  const infra = result.threat_infrastructure;
  const risk = result.risk_assessment;

  // Determine Layer 1 status
  const l1Status = features ? 'COMPLETED' : 'PENDING';
  const l1Detail = features ? `${features.url_length} chars · ${features.suspicious_keyword_count} keywords` : 'Waiting';

  // Determine Layer 2 status
  const l2Status = domain?.dns?.dns_resolved ? 'COMPLETED' : domain?.dns ? 'PARTIAL' : 'PENDING';
  const l2Detail = domain?.dns?.dns_resolved
    ? `Resolved (${domain.dns.ip_count} IPs)`
    : domain?.dns
    ? 'Unresolved DNS'
    : 'Waiting';

  // Determine Layer 3 status
  const l3Status = features?.is_ip_address
    ? 'IP_HOST'
    : domain?.registration?.is_data_available
    ? 'COMPLETED'
    : domain?.registration
    ? 'UNAVAILABLE'
    : 'PENDING';
  const l3Detail = features?.is_ip_address
    ? 'Direct IP (WHOIS N/A)'
    : domain?.registration?.is_nrd
    ? 'NRD Alert (<=30d)'
    : domain?.registration?.is_data_available
    ? 'RDAP Verified'
    : 'RDAP Timeout / Excluded';

  // Determine Layer 4 status
  const l4Status = risk ? 'COMPLETED' : 'PENDING';
  const l4Detail = risk ? `Verdict: ${risk.verdict}` : 'Waiting';

  const tabIdMap = {
    '01': 'tab1_lexical',
    '02': 'tab2_dns',
    '03': 'tab3_domain',
    '04': 'tab4_verdict',
  };

  const layers = [
    { num: '01', title: 'URL Lexical', status: l1Status, detail: l1Detail, tabId: 'tab1_lexical' },
    { num: '02', title: 'DNS & Network', status: l2Status, detail: l2Detail, tabId: 'tab2_dns' },
    { num: '03', title: 'Domain & Intel', status: l3Status, detail: l3Detail, tabId: 'tab3_domain' },
    { num: '04', title: 'Risk & Verdict', status: l4Status, detail: l4Detail, tabId: 'tab4_verdict' },
  ];

  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
      {layers.map((l) => {
        const isSuccess = l.status === 'COMPLETED';
        const isPartial = l.status === 'PARTIAL' || l.status === 'IP_HOST';
        const isUnavailable = l.status === 'UNAVAILABLE';
        const isCurrentActive = activeTab === l.tabId;

        const badgeClass =
          isSuccess
            ? isDark ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-emerald-50 text-emerald-700 border-emerald-200'
            : isPartial
            ? isDark ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30' : 'bg-cyan-50 text-cyan-700 border-cyan-200'
            : isUnavailable
            ? isDark ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' : 'bg-amber-50 text-amber-800 border-amber-200'
            : isDark ? 'bg-slate-800 text-slate-400 border-slate-700' : 'bg-slate-100 text-slate-600 border-slate-300';

        const Tag = onSelectTab ? 'button' : 'div';

        return (
          <Tag
            key={l.num}
            type={onSelectTab ? 'button' : undefined}
            onClick={onSelectTab ? () => onSelectTab(l.tabId) : undefined}
            className={`flex items-center gap-2.5 rounded-lg p-2.5 border c1-kpi-card transition text-left ${
              onSelectTab ? 'cursor-pointer hover:border-blue-500/50' : ''
            } ${
              isCurrentActive
                ? isDark
                  ? 'bg-slate-900 border-cyan-500 ring-1 ring-cyan-500/50 shadow-sm'
                  : 'bg-blue-50/60 border-blue-500 ring-1 ring-blue-500/40 shadow-xs'
                : isDark
                ? 'bg-slate-900/80 border-slate-800'
                : 'bg-white border-slate-200 shadow-xs'
            }`}
          >
            <span className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-md font-mono text-xs font-bold ${
              isCurrentActive
                ? 'bg-blue-600 text-white'
                : isDark ? 'bg-slate-800 text-cyan-400' : 'bg-blue-50 text-blue-700 border border-blue-200'
            }`}>
              {l.num}
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex items-center justify-between">
                <span className={`truncate text-xs font-semibold ${isDark ? 'text-slate-200' : 'text-slate-800'}`}>{l.title}</span>
                <span className={`rounded px-1.5 py-0.2 text-[0.5625rem] font-bold border ${badgeClass}`}>
                  {l.status}
                </span>
              </div>
              <p className={`truncate font-mono text-[0.625rem] ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>{l.detail}</p>
            </div>
          </Tag>
        );
      })}
    </div>
  );
}
