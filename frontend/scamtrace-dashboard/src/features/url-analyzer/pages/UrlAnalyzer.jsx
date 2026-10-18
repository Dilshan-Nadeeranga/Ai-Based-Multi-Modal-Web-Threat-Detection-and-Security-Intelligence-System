import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  Search,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Globe,
  Code,
  Key,
  Terminal,
  Cpu,
  ExternalLink,
  BrainCircuit,
  Scale,
  Sliders,
  CheckCircle2,
  Info,
  Network,
  Fingerprint,
  Lock,
  Unlock,
  Server,
  Layers,
  Copy,
  Check,
  Zap,
  ArrowRight,
  Clock,
  Radio,
  Compass,
  AlertCircle,
  Database,
  BarChart3,
  RefreshCw,
  FileCode,
  Activity,
  XCircle,
  ArrowRightLeft,
  Sparkles,
  Sun,
  Moon,
  Shield,
  Gauge,
} from 'lucide-react';
import AppShell from '../../../components/AppShell.jsx';
import {
  ChannelWeightDonutChart,
  RenormalizationBarChart,
  RiskScoreBreakdownChart,
  RadialScoreGauge,
  LayerStatusPipeline,
  SCORING_CHANNELS,
} from '../components/AnalysisCharts.jsx';
import ActiveWeightsSection from '../components/ActiveWeightsSection.jsx';
import {
  SocCard,
  SocSectionHeader,
  SocSubCard,
  SocRow,
  SocKpiTile,
} from '../components/SocCard.jsx';
import { useC1Theme, C1ThemeContext } from '../hooks/useC1Theme.js';
import '../c1.css';


// Color and tone helpers
const TONES = {
  danger: 'text-rose-400 font-bold',
  warn: 'text-amber-400 font-semibold',
  ok: 'text-emerald-400 font-medium',
  cyan: 'text-cyan-300 font-medium',
  muted: 'text-slate-500',
  default: 'text-slate-200',
};

function scoreTone(score) {
  if (score >= 60) return 'danger';
  if (score >= 25) return 'amber';
  return 'safe';
}

const SCORE_STYLES = {
  danger: {
    text: 'text-rose-400',
    badge: 'bg-rose-500/15 text-rose-300 border border-rose-500/40',
    border: 'border-rose-500',
    bar: 'bg-rose-500',
    Icon: ShieldAlert,
    label: 'High Risk / Threat',
  },
  amber: {
    text: 'text-amber-400',
    badge: 'bg-amber-500/15 text-amber-300 border border-amber-500/40',
    border: 'border-amber-500',
    bar: 'bg-amber-500',
    Icon: AlertTriangle,
    label: 'Suspicious / Warning',
  },
  safe: {
    text: 'text-emerald-400',
    badge: 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/40',
    border: 'border-emerald-500',
    bar: 'bg-emerald-500',
    Icon: ShieldCheck,
    label: 'Benign / Safe',
  },
};

const VERDICT_STYLES = {
  PHISHING: {
    badge: 'bg-rose-500/20 text-rose-300 border border-rose-500/40 shadow-[0_0_12px_rgba(244,63,94,0.3)]',
    text: 'text-rose-400',
    border: 'border-rose-500',
    Icon: AlertTriangle,
    label: 'PHISHING',
    description: 'Suspicious login/credential or account verification patterns detected.',
  },
  MALICIOUS: {
    badge: 'bg-red-500/25 text-red-200 border border-red-500/50 shadow-[0_0_12px_rgba(239,68,68,0.3)]',
    text: 'text-red-400',
    border: 'border-red-600',
    Icon: ShieldAlert,
    label: 'MALICIOUS',
    description: 'Strong evidence of malware distribution, exploit, or confirmed threat feed match.',
  },
  SUSPICIOUS: {
    badge: 'bg-amber-500/20 text-amber-300 border border-amber-500/40 shadow-[0_0_12px_rgba(245,158,11,0.25)]',
    text: 'text-amber-400',
    border: 'border-amber-500',
    Icon: AlertTriangle,
    label: 'SUSPICIOUS',
    description: 'Elevated risk score with insufficient evidence to distinguish phishing from malware.',
  },
  SAFE: {
    badge: 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-[0_0_12px_rgba(16,185,129,0.25)]',
    text: 'text-emerald-400',
    border: 'border-emerald-500',
    Icon: ShieldCheck,
    label: 'SAFE',
    description: 'Clean lexical structure, established domain, and no threat indicators observed.',
  },
};

function getVerdictInfo(verdictStr, fallbackRiskLevel = 'SAFE') {
  const norm = (verdictStr || fallbackRiskLevel || 'SAFE').toUpperCase();
  if (norm.includes('PHISH')) return VERDICT_STYLES.PHISHING;
  if (norm.includes('MALICIOUS') || norm.includes('HIGH')) return VERDICT_STYLES.MALICIOUS;
  if (norm.includes('SUSPICIOUS') || norm.includes('WARN')) return VERDICT_STYLES.SUSPICIOUS;
  if (norm.includes('SAFE') || norm.includes('LOW') || norm.includes('BENIGN')) return VERDICT_STYLES.SAFE;
  return VERDICT_STYLES.SUSPICIOUS;
}

// Sample test URLs for instant demonstration
const SAMPLE_PRESETS = [
  {
    label: 'Clean Domain',
    url: 'https://google.com',
    type: 'safe',
    desc: 'Established domain with valid SSL and clean character distribution',
  },
  {
    label: 'Commercial (Tracking Token)',
    url: 'https://incarnage.com/?srsltid=AU7gw4Xh3ZyZaUEd7vknNJwSALGGys4-rUHXNgX9HwyRGK2QXX7UpLyN',
    type: 'safe',
    desc: 'High-entropy query parameter disambiguated by base-URL entropy (FP Reduction Novelty)',
  },
  {
    label: 'PayPal Phishing Lookalike',
    url: 'http://login.paypal.verify-account.com/auth',
    type: 'danger',
    desc: 'Suspicious brand keywords, high subdomain depth, unencrypted HTTP',
  },
  {
    label: 'Malware Direct IP Host',
    url: 'http://123.9.197.209:60402/bin.sh',
    type: 'danger',
    desc: 'Direct IP host, non-standard high port 60402, shell dropper script',
  },
  {
    label: 'Shortener (Redirect Trace)',
    url: 'https://tinyurl.com/5n7v48m2',
    type: 'amber',
    desc: 'Shortened URL requiring safe SSRF-protected redirection unmasking',
  },
];

export default function UrlAnalyzer() {
  const { theme, toggleTheme, isDark } = useC1Theme();
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('tab1_lexical');
  const [copied, setCopied] = useState(false);
  const [nominalWeights, setNominalWeights] = useState({});

  // Fetch nominal scoring weights on mount
  useEffect(() => {
    async function loadWeights() {
      try {
        const c1Url = import.meta.env.VITE_C1_URL || 'http://localhost:8001';
        const res = await axios.get(`${c1Url}/api/v1/scoring-weights`);
        if (res.data?.nominal_weights) {
          setNominalWeights(res.data.nominal_weights);
        }
      } catch {
        // Fallback already provided in SCORING_CHANNELS
      }
    }
    loadWeights();
  }, []);

  // Analyze URL against backend
  const handleAnalyze = async (e, customUrl) => {
    if (e) e.preventDefault();
    const targetUrl = (customUrl || urlInput).trim();
    if (!targetUrl) return;

    if (customUrl) {
      setUrlInput(customUrl);
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const gatewayUrl = import.meta.env.VITE_GATEWAY_URL || 'http://localhost:5000';
      const c1Url = import.meta.env.VITE_C1_URL || 'http://localhost:8001';

      let response;
      try {
        // Direct C1 service call
        response = await axios.post(`${c1Url}/analyze-url`, { url: targetUrl });
      } catch {
        // Fallback to API Gateway
        const gwRes = await axios.post(`${gatewayUrl}/api/analyze`, { url: targetUrl });
        response = { data: gwRes.data.component_results?.c1_url_domain || gwRes.data };
      }

      setResult(response.data);
      // Auto-focus on Tab 1 upon successful analysis
      setActiveTab('tab1_lexical');
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to complete 4-layer URL analysis.');
    } finally {
      setLoading(false);
    }
  };

  const copyUrl = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Helper flags and entities from real response
  const features = result?.features;
  const domain = result?.domain_intelligence;
  const infra = result?.threat_infrastructure;
  const ml = result?.ml_prediction;
  const risk = result?.risk_assessment;

  // Tab definitions with prominent visual indicators and saturated cyber accents
  const TABS = [
    {
      id: 'tab1_lexical',
      layerNumber: 'Layer 01',
      title: 'URL Lexical Analysis',
      subtitle: '57 Features · Entropy · Obfuscation',
      accentColor: '#2563EB', // Vivid Electric Blue / Royal Blue
      accentClass: 'blue',
      icon: Search,
      glowColor: 'rgba(37, 99, 235, 0.35)',
      badgeText: () => {
        if (!features) return 'Feature Space Ready';
        const count =
          (features.suspicious_keyword_count || 0) +
          (features.has_homoglyphs ? 1 : 0) +
          (features.is_ip_address ? 1 : 0) +
          (features.is_double_encoded ? 1 : 0) +
          (features.has_at_symbol ? 1 : 0) +
          (features.is_suspicious_tld ? 1 : 0);
        return count > 0 ? `${count} Suspicious Flags` : 'Clean Structure (57 Feat.)';
      },
      badgeClass: () => {
        if (!features) {
          return isDark ? 'bg-slate-800 text-slate-400 border-slate-700' : 'bg-slate-100 text-slate-600 border-slate-200';
        }
        const count =
          (features.suspicious_keyword_count || 0) +
          (features.has_homoglyphs ? 1 : 0) +
          (features.is_ip_address ? 1 : 0);
        return count > 0
          ? isDark ? 'bg-rose-500/15 text-rose-300 border-rose-500/40' : 'bg-rose-50 text-rose-700 border-rose-200'
          : isDark ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40' : 'bg-emerald-50 text-emerald-700 border-emerald-200';
      },
    },
    {
      id: 'tab2_dns',
      layerNumber: 'Layer 02',
      title: 'DNS & Network Analysis',
      subtitle: 'Records · Redirect Chains · DGA',
      accentColor: '#0D9488', // Vibrant Teal
      accentClass: 'teal',
      icon: Network,
      glowColor: 'rgba(13, 148, 136, 0.35)',
      badgeText: () => {
        if (!domain?.dns) return 'DNS & Hop Tracer Ready';
        if (!domain.dns.dns_resolved) return 'NXDOMAIN / Unresolved';
        return `${domain.dns.ip_count} IP(s) Resolved`;
      },
      badgeClass: () => {
        if (!domain?.dns) {
          return isDark ? 'bg-slate-800 text-slate-400 border-slate-700' : 'bg-slate-100 text-slate-600 border-slate-200';
        }
        return domain.dns.dns_resolved
          ? isDark ? 'bg-teal-500/15 text-teal-300 border-teal-500/40' : 'bg-teal-50 text-teal-700 border-teal-200'
          : isDark ? 'bg-amber-500/15 text-amber-300 border-amber-500/40' : 'bg-amber-50 text-amber-800 border-amber-200';
      },
    },
    {
      id: 'tab3_domain',
      layerNumber: 'Layer 03',
      title: 'Domain Intelligence & Reputation',
      subtitle: 'WHOIS/RDAP · Age · Threat Feeds',
      accentColor: '#7C3AED', // Rich Violet
      accentClass: 'violet',
      icon: Shield,
      glowColor: 'rgba(124, 58, 237, 0.35)',
      badgeText: () => {
        if (!result) return 'RDAP & NRD Engine Ready';
        if (features?.is_ip_address) return 'IP Host (No Domain)';
        if (!domain?.registration) return 'Unavailable';
        if (domain.registration.is_nrd) return 'NRD Alert (<=30d)';
        if (domain.registration.age_days !== null && domain.registration.age_days !== undefined) {
          return `${Math.floor(domain.registration.age_days / 365)}y Domain Age`;
        }
        return domain.registration.data_source || 'Available';
      },
      badgeClass: () => {
        if (!result) {
          return isDark ? 'bg-slate-800 text-slate-400 border-slate-700' : 'bg-slate-100 text-slate-600 border-slate-200';
        }
        if (domain?.registration?.is_nrd || domain?.reputation?.is_known_threat) {
          return isDark ? 'bg-rose-500/15 text-rose-300 border-rose-500/40' : 'bg-rose-50 text-rose-700 border-rose-200';
        }
        return isDark ? 'bg-purple-500/15 text-purple-300 border-purple-500/40' : 'bg-purple-50 text-purple-700 border-purple-200';
      },
    },
    {
      id: 'tab4_verdict',
      layerNumber: 'Layer 04',
      title: 'Risk Assessment & Final Verdict',
      subtitle: 'Dynamic Renormalization · XAI · RF',
      accentColor: '#D97706', // Strong Amber / Orange
      accentClass: 'amber',
      icon: Activity,
      glowColor: 'rgba(217, 119, 6, 0.35)',
      badgeText: () => {
        if (!result) return 'Synthesis Engine Ready';
        return `Verdict: ${result.verdict || result.risk_level}`;
      },
      badgeClass: () => {
        if (!result) {
          return isDark ? 'bg-slate-800 text-slate-400 border-slate-700' : 'bg-slate-100 text-slate-600 border-slate-200';
        }
        const tone = scoreTone(result.score);
        return SCORE_STYLES[tone].badge;
      },
    },
  ];


  return (
    <C1ThemeContext.Provider value={{ theme, toggleTheme, isDark }}>
      <AppShell title="Threat Analysis">
        {/* Dynamic Theme Cybersecurity SOC Wrapper */}
        <div
          className="c1-console min-h-screen transition-colors duration-200 selection:bg-blue-500/30 selection:text-blue-200"
          data-c1-theme={theme}
          style={{
            backgroundColor: isDark ? '#030712' : '#f8fafc',
            color: isDark ? '#f8fafc' : '#0f172a',
          }}
        >
          <div className="mx-auto max-w-7xl px-4 py-6 md:px-8 space-y-6">

            {/* ================================================================= */}
            {/* 1. TOP HEADER & PROMINENT URL ANALYSIS CONTROLS */}
            {/* ================================================================= */}
            <header
              className={`rounded-2xl p-6 border shadow-2xl backdrop-blur-xl transition-all duration-200 c1-hover-card ${
                isDark
                  ? 'bg-gradient-to-r from-[#0b1329] via-[#09142f] to-[#0b1329] border-cyan-500/30 text-slate-100 shadow-[0_4px_30px_rgba(6,182,212,0.12)]'
                  : 'bg-white border-blue-500/30 text-slate-900 shadow-[0_8px_30px_rgba(37,99,235,0.08)] ring-1 ring-blue-500/10'
              }`}
            >
              <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
                <div>
                  <div className="flex items-center gap-2.5">
                    <span
                      className={`flex h-7 w-7 items-center justify-center rounded-lg border ${
                        isDark ? 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30' : 'bg-blue-50 text-blue-600 border-blue-200'
                      }`}
                    >
                      <Radio className="h-4 w-4 animate-pulse" />
                    </span>
                    <span className={`font-mono text-xs font-bold uppercase tracking-widest ${isDark ? 'text-cyan-400' : 'text-blue-700'}`}>
                      Security Operations Center · Component C1
                    </span>
                    <span
                      className={`hidden sm:inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[0.6875rem] font-medium border ${
                        isDark ? 'bg-slate-800 text-slate-300 border-slate-700' : 'bg-slate-100 text-slate-700 border-slate-200'
                      }`}
                    >
                      <Sparkles className={`h-3 w-3 ${isDark ? 'text-cyan-400' : 'text-blue-600'}`} /> Research-Grade Framework
                    </span>
                  </div>
                  <h1 className={`mt-1 font-manrope text-2xl font-extrabold tracking-tight sm:text-3xl ${isDark ? 'text-white' : 'text-slate-900'}`}>
                    C1 — Intelligent URL & Domain Analyzer
                  </h1>
                  <p className={`mt-1 text-xs sm:text-sm ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
                    Multi-Layer URL and Domain Threat Intelligence with Availability-Aware Weight Renormalization.
                  </p>
                </div>

                {/* Status Badges & Light/Dark Theme Switcher */}
                <div className="flex flex-wrap items-center gap-2.5 text-xs">
                  {/* Theme Switcher Toggle */}
                  <button
                    type="button"
                    onClick={toggleTheme}
                    aria-label={`Switch to ${isDark ? 'Light' : 'Dark'} Mode`}
                    title={`Switch to ${isDark ? 'Light' : 'Dark'} Mode`}
                    className={`group relative flex items-center gap-2.5 rounded-xl px-3.5 py-2 font-medium text-xs transition-all duration-200 border cursor-pointer c1-kpi-card ${
                      isDark
                        ? 'bg-slate-950/80 text-slate-200 border-slate-700 hover:bg-slate-800 hover:border-cyan-400/50 shadow-md'
                        : 'bg-slate-50 text-slate-800 border-slate-300 hover:bg-white hover:border-blue-500 shadow-sm'
                    }`}
                  >
                    <div className="relative flex h-5 w-5 items-center justify-center">
                      {isDark ? (
                        <Sun className="h-4 w-4 text-amber-400 transition-transform duration-300 group-hover:rotate-45" />
                      ) : (
                        <Moon className="h-4 w-4 text-blue-600 transition-transform duration-300 group-hover:-rotate-12" />
                      )}
                    </div>
                    <span className="font-semibold">
                      {isDark ? 'Dark Mode' : 'Light Mode'}
                    </span>
                    <span
                      className={`flex h-2 w-2 rounded-full ${
                        isDark ? 'bg-cyan-400 shadow-[0_0_8px_rgba(6,182,212,0.8)]' : 'bg-blue-600 shadow-[0_0_8px_rgba(37,99,235,0.6)]'
                      }`}
                    />
                  </button>

                  <span
                    className={`inline-flex items-center gap-1.5 rounded-xl px-3 py-2 font-mono border ${
                      isDark ? 'bg-slate-950/80 text-slate-300 border-slate-800' : 'bg-slate-50 text-slate-700 border-slate-200'
                    }`}
                  >
                    <span className="h-2 w-2 rounded-full bg-emerald-400 animate-ping" />
                    Engine: <strong className={isDark ? 'text-white' : 'text-slate-900'}>v1.0.0 Online</strong>
                  </span>
                  <span
                    className={`inline-flex items-center gap-1.5 rounded-xl px-3 py-2 font-mono border ${
                      isDark ? 'bg-slate-950/80 text-slate-300 border-slate-800' : 'bg-slate-50 text-slate-700 border-slate-200'
                    }`}
                  >
                    <BrainCircuit className={`h-3.5 w-3.5 ${isDark ? 'text-cyan-400' : 'text-blue-600'}`} />
                    Random Forest <strong className={isDark ? 'text-white' : 'text-slate-900'}>(57-D)</strong>
                  </span>
                </div>
              </div>

              {/* URL Input Form */}
              <form onSubmit={handleAnalyze} className="mt-6">
                <div className="relative flex flex-col gap-2.5 sm:flex-row sm:items-center">
                  <div className="relative flex-1">
                    <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-4">
                      <Search className={`h-5 w-5 ${isDark ? 'text-cyan-400' : 'text-blue-600'}`} aria-hidden="true" />
                    </div>
                    <input
                      type="text"
                      value={urlInput}
                      onChange={(e) => setUrlInput(e.target.value)}
                      placeholder="Enter suspicious URL or domain (e.g. https://bank-verify-account.com/auth or http://1.2.3.4/bin.sh)"
                      className={`w-full rounded-xl py-3.5 pl-11 pr-4 font-mono text-sm placeholder-slate-400 border shadow-inner transition focus:outline-none focus:ring-2 ${
                        isDark
                          ? 'bg-slate-950/90 text-slate-100 border-slate-700/80 focus:border-cyan-400 focus:ring-cyan-500/30'
                          : 'bg-white text-slate-900 border-slate-300 focus:border-blue-500 focus:ring-blue-500/20'
                      }`}
                      disabled={loading}
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={loading || !urlInput.trim()}
                    className="inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 px-6 py-3.5 font-manrope text-sm font-bold text-white shadow-[0_0_20px_rgba(37,99,235,0.4)] transition disabled:opacity-50 disabled:shadow-none cursor-pointer"
                  >
                    {loading ? (
                      <>
                        <RefreshCw className="h-4 w-4 animate-spin" />
                        <span>Analyzing URL…</span>
                      </>
                    ) : (
                      <>
                        <Zap className="h-4 w-4" />
                        <span>Analyze URL</span>
                      </>
                    )}
                  </button>
                </div>

                {/* Sample Threat Vectors Presets */}
                <div className="mt-3.5 flex flex-wrap items-center gap-1.5 text-xs">
                  <span className={`text-[0.6875rem] font-bold uppercase tracking-wider mr-1 ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
                    Presets:
                  </span>
                  {SAMPLE_PRESETS.map((preset, idx) => (
                    <button
                      key={idx}
                      type="button"
                      onClick={() => handleAnalyze(null, preset.url)}
                      className={`rounded-lg px-2.5 py-1 font-mono text-[0.6875rem] border transition cursor-pointer ${
                        isDark
                          ? 'bg-slate-950/80 text-slate-300 border-slate-800 hover:border-cyan-500/50 hover:bg-slate-800 hover:text-white'
                          : 'bg-slate-50 text-slate-700 border-slate-200 hover:border-blue-500 hover:bg-blue-50 hover:text-blue-900'
                      }`}
                      title={preset.desc}
                    >
                      {preset.label}
                    </button>
                  ))}
                </div>
              </form>

              {/* Error Banner */}
              {error && (
                <div className={`mt-4 flex items-center gap-3 rounded-xl p-3.5 text-xs border ${
                  isDark ? 'bg-rose-500/10 text-rose-300 border-rose-500/30' : 'bg-rose-50 text-rose-800 border-rose-200'
                }`}>
                  <AlertCircle className="h-5 w-5 shrink-0 text-rose-500" />
                  <div className="flex-1 font-mono">{error}</div>
                </div>
              )}
            </header>

            {/* ================================================================= */}
            {/* 3. FOUR HIGHLY VISIBLE COLOR-CODED ANALYSIS TABS */}
            {/* ================================================================= */}
            <section className="space-y-2">
              <div className="flex items-center justify-between px-1">
                <div className="flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-blue-500 animate-pulse" />
                  <span className={`font-mono text-xs font-bold uppercase tracking-widest ${isDark ? 'text-slate-300' : 'text-slate-700'}`}>
                    4-Layer Security Intelligence Pipeline
                  </span>
                </div>
                <span className={`text-[0.6875rem] font-mono ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
                  Select tab to inspect layer telemetry
                </span>
              </div>

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                {TABS.map((tab) => {
                  const Icon = tab.icon;
                  const isActive = activeTab === tab.id;
                  const badgeText = tab.badgeText();
                  const badgeClass = tab.badgeClass();

                  return (
                    <button
                      key={tab.id}
                      type="button"
                      onClick={() => setActiveTab(tab.id)}
                      className={`group relative flex flex-col justify-between overflow-hidden rounded-2xl p-4 sm:p-5 text-left transition-all c1-tab-card cursor-pointer border ${
                        isActive
                          ? isDark
                            ? 'bg-[#0f172a] shadow-xl ring-2'
                            : 'bg-white shadow-lg ring-2'
                          : isDark
                          ? 'bg-[#0b1329]/90 border-slate-800/90 hover:border-slate-700'
                          : 'bg-white border-slate-200 hover:border-slate-300 shadow-xs'
                      }`}
                      style={{
                        borderColor: isActive ? tab.accentColor : undefined,
                        boxShadow: isActive ? `0 8px 28px -4px ${tab.accentColor}35, 0 0 16px ${tab.accentColor}25` : undefined,
                        ['--tw-ring-color']: isActive ? tab.accentColor : undefined,
                      }}
                    >
                      {/* Top Accent Strip */}
                      <div
                        className="absolute top-0 left-0 right-0 h-1.5 transition-all duration-200"
                        style={{
                          backgroundColor: tab.accentColor,
                          opacity: isActive ? 1 : 0.65,
                        }}
                      />

                      <div>
                        {/* Header row: Icon & Layer Number & Active Badge */}
                        <div className="flex items-center justify-between pt-1">
                          <span
                            className="flex h-11 w-11 items-center justify-center rounded-xl border transition-all duration-200 shadow-xs"
                            style={{
                              backgroundColor: `${tab.accentColor}18`,
                              color: tab.accentColor,
                              borderColor: `${tab.accentColor}40`,
                            }}
                          >
                            <Icon className="h-5 w-5" aria-hidden="true" />
                          </span>

                          <div className="flex items-center gap-1.5">
                            <span
                              className="font-mono text-[0.6875rem] font-extrabold uppercase tracking-wider px-2 py-0.5 rounded-md border"
                              style={{
                                color: tab.accentColor,
                                borderColor: `${tab.accentColor}40`,
                                backgroundColor: `${tab.accentColor}12`,
                              }}
                            >
                              {tab.layerNumber}
                            </span>
                            {isActive && (
                              <span
                                className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 font-mono text-[0.625rem] font-extrabold uppercase text-white shadow-xs"
                                style={{ backgroundColor: tab.accentColor }}
                              >
                                <span className="h-1.5 w-1.5 rounded-full bg-white animate-pulse" />
                                Active
                              </span>
                            )}
                          </div>
                        </div>

                        {/* Titles */}
                        <div className="mt-3.5">
                          <h3 className={`font-manrope text-sm sm:text-base font-extrabold tracking-tight transition-colors ${
                            isActive
                              ? isDark ? 'text-white' : 'text-slate-900'
                              : isDark ? 'text-slate-200 group-hover:text-white' : 'text-slate-800 group-hover:text-slate-900'
                          }`}>
                            {tab.title}
                          </h3>
                          <p className={`text-xs mt-1 leading-relaxed ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
                            {tab.subtitle}
                          </p>
                        </div>
                      </div>

                      {/* Real Status Badge Pill */}
                      <div className={`mt-4 pt-3 border-t flex items-center justify-between ${isDark ? 'border-slate-800/60' : 'border-slate-100'}`}>
                        <span className={`inline-flex items-center gap-1 rounded-md px-2.5 py-1 font-mono text-[0.6875rem] font-bold border transition ${badgeClass}`}>
                          {badgeText}
                        </span>
                        <ArrowRight
                          className={`h-4 w-4 transition-transform duration-200 ${
                            isActive ? 'translate-x-1 opacity-100' : 'opacity-40 group-hover:translate-x-0.5 group-hover:opacity-80'
                          }`}
                          style={{ color: tab.accentColor }}
                        />
                      </div>
                    </button>
                  );
                })}
              </div>
            </section>

            {/* ================================================================= */}
            {/* LOADING STATE WITH MULTI-STEP PIPELINE */}
            {/* ================================================================= */}
            {loading && (
              <SocCard className="py-12 text-center border-cyan-500/30" glow>
                <div className="mx-auto max-w-md space-y-4">
                  <div className="relative mx-auto flex h-16 w-16 items-center justify-center">
                    <div className="absolute inset-0 rounded-full border-2 border-cyan-500/20 animate-ping" />
                    <div className="flex h-12 w-12 items-center justify-center rounded-full bg-cyan-500/20 text-cyan-400 border border-cyan-500/40">
                      <RefreshCw className="h-6 w-6 animate-spin" />
                    </div>
                  </div>
                  <h3 className="font-manrope text-lg font-bold">
                    Executing 4-Layer Cyber Threat Evaluation
                  </h3>
                  <p className="text-xs text-slate-400 leading-relaxed font-mono">
                    Extracting 57 lexical features · Querying DNS · Tracing redirect hops · Random Forest supervised classification
                  </p>
                  <div className={`space-y-1.5 text-left text-xs font-mono p-3 rounded-xl border ${
                    isDark ? 'bg-slate-950/80 border-slate-800 text-slate-400' : 'bg-slate-50 border-slate-200 text-slate-600'
                  }`}>
                    <div className="flex items-center gap-2 text-cyan-400 dark:text-cyan-300 font-semibold">
                      <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-pulse" />
                      [1/4] Feature extraction & Shannon entropy calculation...
                    </div>
                    <div className="flex items-center gap-2 text-slate-500">
                      <span className="h-1.5 w-1.5 rounded-full bg-slate-400" />
                      [2/4] Controlled redirect trace & DNS infrastructure check...
                    </div>
                    <div className="flex items-center gap-2 text-slate-500">
                      <span className="h-1.5 w-1.5 rounded-full bg-slate-400" />
                      [3/4] RDAP registration age & DGA phonetic modeling...
                    </div>
                    <div className="flex items-center gap-2 text-slate-500">
                      <span className="h-1.5 w-1.5 rounded-full bg-slate-400" />
                      [4/4] Dynamic weight renormalization & final verdict synthesis...
                    </div>
                  </div>
                </div>
              </SocCard>
            )}

            {/* ================================================================= */}
            {/* EMPTY STATE BEFORE ANALYSIS */}
            {/* ================================================================= */}
            {!loading && !result && (
              <SocCard className="py-14 text-center border-slate-800">
                <div className="mx-auto max-w-lg space-y-4">
                  <div className={`mx-auto flex h-16 w-16 items-center justify-center rounded-2xl border ${
                    isDark ? 'bg-slate-800/80 text-cyan-400 border-slate-700' : 'bg-blue-50 text-blue-600 border-blue-200'
                  }`}>
                    <Compass className="h-8 w-8 animate-pulse" />
                  </div>
                  <h3 className="font-manrope text-xl font-bold">
                    Security Operations Console Ready
                  </h3>
                  <p className={`text-xs leading-relaxed ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
                    Enter any suspected URL or select a sample preset above to execute multi-layer threat analysis.
                    Static inspection evaluates lexical patterns, DNS infrastructure, WHOIS/RDAP age, DGA likelihood,
                    and supervised machine learning without rendering malicious payloads.
                  </p>

                  {/* 4 Layer Capabilities Overview */}
                  <div className="grid grid-cols-2 gap-2 text-left pt-2 sm:grid-cols-4">
                    <div className={`rounded-xl p-3 border c1-kpi-card ${isDark ? 'bg-slate-950/80 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
                      <div className="text-[0.625rem] font-bold uppercase text-blue-500">Layer 01</div>
                      <div className="font-semibold text-xs mt-0.5">Lexical (57D)</div>
                      <div className="text-[0.625rem] text-slate-500 mt-0.5">Shannon Entropy & Syntax</div>
                    </div>
                    <div className={`rounded-xl p-3 border c1-kpi-card ${isDark ? 'bg-slate-950/80 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
                      <div className="text-[0.625rem] font-bold uppercase text-teal-500">Layer 02</div>
                      <div className="font-semibold text-xs mt-0.5">DNS & Network</div>
                      <div className="text-[0.625rem] text-slate-500 mt-0.5">Records & Redirect Trace</div>
                    </div>
                    <div className={`rounded-xl p-3 border c1-kpi-card ${isDark ? 'bg-slate-950/80 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
                      <div className="text-[0.625rem] font-bold uppercase text-purple-500">Layer 03</div>
                      <div className="font-semibold text-xs mt-0.5">Domain Intel</div>
                      <div className="text-[0.625rem] text-slate-500 mt-0.5">NRD & DGA Algorithms</div>
                    </div>
                    <div className={`rounded-xl p-3 border c1-kpi-card ${isDark ? 'bg-slate-950/80 border-slate-800' : 'bg-slate-50 border-slate-200'}`}>
                      <div className="text-[0.625rem] font-bold uppercase text-amber-500">Layer 04</div>
                      <div className="font-semibold text-xs mt-0.5">XAI & Verdict</div>
                      <div className="text-[0.625rem] text-slate-500 mt-0.5">Dynamic Renormalization</div>
                    </div>
                  </div>
                </div>
              </SocCard>
            )}

            {/* ================================================================= */}
            {/* RESULT LOADED: SUMMARY STRIP, WEIGHTS NOVELTY, AND LAYER DETAILS */}
            {/* ================================================================= */}
            {!loading && result && (
              <div className="space-y-6">

                {/* ========================================================= */}
                {/* MAIN WEBPAGE CONTENT & 4-LAYER ANALYSIS DETAILS */}
                {/* Primary analysis information, charts, and telemetry at the top */}
                {/* ========================================================= */}

              {/* ========================================================= */}
              {/* TAB 1: URL LEXICAL ANALYSIS */}
              {/* ========================================================= */}
              {activeTab === 'tab1_lexical' && features && (
                <div className="space-y-6 animate-in fade-in duration-200">
                  {/* Layer Header */}
                  <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl bg-slate-900/80 p-4 border border-slate-800">
                    <div className="flex items-center gap-3">
                      <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                        <Fingerprint className="h-5 w-5" />
                      </span>
                      <div>
                        <h3 className="font-manrope text-base font-bold text-white">
                          Layer 1: URL Lexical & Structural Heuristics
                        </h3>
                        <p className="text-xs text-slate-400">
                          57 canonical features evaluated without external network dependency.
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="rounded-md bg-slate-800 px-2.5 py-1 font-mono text-xs font-semibold text-cyan-300 border border-slate-700">
                        Feature Space: 57 Dims
                      </span>
                      {features.has_tracking_param && (
                        <span className="rounded-md bg-emerald-500/15 px-2.5 py-1 font-mono text-xs font-semibold text-emerald-300 border border-emerald-500/30">
                          Tracking Disambiguated
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Parsed Components Anatomy Card */}
                  <SocCard className="space-y-4">
                    <SocSectionHeader
                      icon={Code}
                      title="Parsed URL Structural Breakdown"
                      subtitle="Anatomical decomposition of the submitted URI according to RFC 3986 specifications."
                    />

                    <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-8 font-mono text-xs">
                      <div className="rounded-lg bg-slate-950 p-2.5 border border-slate-800">
                        <div className="text-[0.625rem] font-bold text-slate-400 uppercase">Scheme</div>
                        <div className="mt-1 font-semibold text-cyan-400">{features.scheme || 'N/A'}</div>
                      </div>
                      <div className="rounded-lg bg-slate-950 p-2.5 border border-slate-800">
                        <div className="text-[0.625rem] font-bold text-slate-400 uppercase">Subdomain</div>
                        <div className="mt-1 truncate font-semibold text-slate-200" title={features.subdomain || 'None'}>
                          {features.subdomain || <span className="text-slate-600 italic">None</span>}
                        </div>
                      </div>
                      <div className="rounded-lg bg-slate-950 p-2.5 border border-slate-800 sm:col-span-2">
                        <div className="text-[0.625rem] font-bold text-slate-400 uppercase">Apex Domain</div>
                        <div className="mt-1 truncate font-semibold text-white" title={features.registered_domain || 'N/A'}>
                          {features.registered_domain || 'N/A'}
                        </div>
                      </div>
                      <div className="rounded-lg bg-slate-950 p-2.5 border border-slate-800">
                        <div className="text-[0.625rem] font-bold text-slate-400 uppercase">TLD</div>
                        <div className="mt-1 font-semibold text-cyan-300">
                          .{features.tld || 'N/A'} {features.is_suspicious_tld && <span className="text-rose-400">(Risky)</span>}
                        </div>
                      </div>
                      <div className="rounded-lg bg-slate-950 p-2.5 border border-slate-800">
                        <div className="text-[0.625rem] font-bold text-slate-400 uppercase">Port</div>
                        <div className="mt-1 font-semibold text-slate-200">
                          {features.port || (features.scheme === 'https' ? '443' : '80')}
                          {!features.is_standard_port && <span className="ml-1 text-rose-400 font-bold">(Non-Std)</span>}
                        </div>
                      </div>
                      <div className="rounded-lg bg-slate-950 p-2.5 border border-slate-800 sm:col-span-2">
                        <div className="text-[0.625rem] font-bold text-slate-400 uppercase">Path</div>
                        <div className="mt-1 truncate font-semibold text-slate-200" title={features.path || '/'}>
                          {features.path || '/'}
                        </div>
                      </div>
                    </div>
                  </SocCard>

                  {/* Metrics KPI Grid */}
                  <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
                    <SocKpiTile label="URL Length" value={features.url_length} unit="chars" tone="cyan" />
                    <SocKpiTile label="Hostname Length" value={features.hostname_length} unit="chars" tone="blue" />
                    <SocKpiTile label="Subdomain Count" value={features.num_subdomains} unit="subdomains" tone={features.num_subdomains > 2 ? 'amber' : 'cyan'} />
                    <SocKpiTile label="Path Depth" value={features.path_depth} unit="segments" tone="cyan" />
                    <SocKpiTile label="Digits Count" value={features.num_digits} unit="digits" tone="purple" />
                    <SocKpiTile label="Special Symbols" value={features.num_special_chars} unit="symbols" tone={features.num_special_chars > 8 ? 'amber' : 'cyan'} />
                  </div>

                  {/* Suspicious Keywords & Security Findings */}
                  <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
                    <SocCard className="space-y-4">
                      <SocSectionHeader
                        icon={AlertTriangle}
                        iconClass="text-amber-400 bg-amber-500/10 border-amber-500/30"
                        title="Suspicious Keyword Telemetry"
                        subtitle="Matches against credential, authentication, and targeted brand keyword dictionaries."
                      />
                      {features.has_suspicious_keyword ? (
                        <div className="space-y-3">
                          <div className="flex flex-wrap gap-1.5">
                            {features.suspicious_keywords_found?.map((kw, i) => (
                              <span
                                key={i}
                                className="inline-flex items-center gap-1 rounded bg-rose-500/15 px-2.5 py-1 font-mono text-xs font-bold text-rose-300 border border-rose-500/30"
                              >
                                <AlertCircle className="h-3 w-3" /> {kw}
                              </span>
                            ))}
                          </div>
                          <p className="text-xs text-rose-300">
                            {features.suspicious_keyword_count} keyword match(es) indicate potential credential theft or spoofing intent.
                          </p>
                        </div>
                      ) : (
                        <div className="rounded-lg bg-emerald-500/10 p-3.5 text-xs text-emerald-300 border border-emerald-500/20 flex items-center gap-2">
                          <CheckCircle2 className="h-4 w-4" /> No suspicious security or banking keywords detected.
                        </div>
                      )}
                    </SocCard>

                    {/* Entropy & Tracking Disambiguation Engine (Research Novelty) */}
                    <SocCard className="space-y-4">
                      <SocSectionHeader
                        icon={Cpu}
                        title="Entropy Engine & Disambiguation"
                        subtitle="Shannon entropy computed with tracking token isolation (Novelty 1)."
                      />
                      <div className="space-y-2">
                        <SocRow
                          label="Base URL Shannon Entropy"
                          value={features.base_url_entropy ? `${features.base_url_entropy.toFixed(3)} bits/char` : 'N/A'}
                          tone={features.base_url_entropy > 4.5 ? 'danger' : 'cyan'}
                        />
                        <SocRow
                          label="Total URL Shannon Entropy"
                          value={features.url_entropy ? `${features.url_entropy.toFixed(3)} bits/char` : 'N/A'}
                        />
                        <SocRow
                          label="Query String Entropy"
                          value={features.query_entropy ? `${features.query_entropy.toFixed(3)} bits/char` : 'None'}
                        />
                        <SocRow
                          label="Marketing Tracking Disambiguation"
                          value={features.has_tracking_param ? 'APPLIED (FP Mitigation Active)' : 'Clean'}
                          tone={features.has_tracking_param ? 'ok' : 'muted'}
                        />
                        <SocRow
                          label="Double Percent-Encoding (%25XX)"
                          value={features.is_double_encoded ? 'DETECTED (Evasion)' : 'None'}
                          tone={features.is_double_encoded ? 'danger' : 'ok'}
                        />
                      </div>
                    </SocCard>
                  </div>
                </div>
              )}

              {/* ========================================================= */}
              {/* TAB 2: DNS & NETWORK ANALYSIS */}
              {/* ========================================================= */}
              {activeTab === 'tab2_dns' && (
                <div className="space-y-6 animate-in fade-in duration-200">
                  {/* Layer Header */}
                  <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl bg-slate-900/80 p-4 border border-slate-800">
                    <div className="flex items-center gap-3">
                      <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                        <Network className="h-5 w-5" />
                      </span>
                      <div>
                        <h3 className="font-manrope text-base font-bold text-white">
                          Layer 2: DNS & Network Threat Infrastructure
                        </h3>
                        <p className="text-xs text-slate-400">
                          Real-time DNS records, Fast-Flux detection, DGA statistical analysis, and SSRF-safe redirect tracing.
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`rounded-md px-2.5 py-1 font-mono text-xs font-semibold border ${
                        domain?.dns?.dns_resolved
                          ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                          : 'bg-rose-500/15 text-rose-300 border-rose-500/30'
                      }`}>
                        {domain?.dns?.dns_resolved ? 'DNS Resolved' : 'Resolution Failed'}
                      </span>
                      <span className="rounded-md bg-emerald-500/15 px-2.5 py-1 font-mono text-xs font-semibold text-emerald-300 border border-emerald-500/30">
                        SSRF Protected
                      </span>
                    </div>
                  </div>

                  {/* DNS Records & Infrastructure Grid */}
                  <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
                    {/* DNS Health */}
                    <SocCard className="space-y-3">
                      <SocSectionHeader icon={Server} title="DNS Resolution & Health" />
                      {domain?.dns ? (
                        <div>
                          <SocRow
                            label="DNS Resolution Status"
                            value={domain.dns.dns_resolved ? 'Resolved Successfully' : 'NXDOMAIN / Unresolved'}
                            tone={domain.dns.dns_resolved ? 'ok' : 'danger'}
                          />
                          <SocRow label="Resolved A-Records (IPv4)" value={`${domain.dns.ip_count || 0} IP(s)`} tone="cyan" />
                          <SocRow
                            label="Minimum Record TTL"
                            value={domain.dns.min_ttl ? `${domain.dns.min_ttl}s` : 'N/A'}
                            tone={domain.dns.min_ttl && domain.dns.min_ttl < 60 ? 'warn' : 'default'}
                          />
                          <SocRow
                            label="Fast-Flux Threat Pattern"
                            value={domain.dns.is_fast_flux ? 'DETECTED (High Turnover)' : 'Clean'}
                            tone={domain.dns.is_fast_flux ? 'danger' : 'ok'}
                          />
                          <SocRow
                            label="Dynamic DNS (DDNS) Provider"
                            value={domain.dns.is_dynamic_dns ? 'YES (Free DDNS Host)' : 'NO'}
                            tone={domain.dns.is_dynamic_dns ? 'warn' : 'ok'}
                          />
                          <SocRow
                            label="Private IP Resolution Leak"
                            value={domain.dns.is_private_ip_resolved ? 'LEAK (RFC1918 Private IP)' : 'Clean (Public IP)'}
                            tone={domain.dns.is_private_ip_resolved ? 'danger' : 'ok'}
                          />
                          <SocRow
                            label="Mail Exchange (MX)"
                            value={domain.dns.has_mx_records ? 'Configured' : 'None'}
                            tone={domain.dns.has_mx_records ? 'ok' : 'muted'}
                          />
                          <SocRow
                            label="SPF Email Authentication"
                            value={domain.dns.has_spf ? 'Configured' : 'Missing'}
                            tone={domain.dns.has_spf ? 'ok' : 'muted'}
                          />
                        </div>
                      ) : (
                        <div className="rounded-lg bg-amber-500/10 p-3.5 text-xs text-amber-300 border border-amber-500/30">
                          DNS resolution data is unavailable for this input.
                        </div>
                      )}
                    </SocCard>

                    {/* Discovered DNS Records (A, AAAA, MX, NS) */}
                    <SocCard className="space-y-4 lg:col-span-2">
                      <SocSectionHeader icon={Database} title="Discovered DNS Resource Records" />

                      {domain?.dns && domain.dns.dns_resolved ? (
                        <div className="space-y-4">
                          {/* A Records */}
                          <div>
                            <span className="text-[0.625rem] font-bold uppercase tracking-wider text-slate-400">
                              IPv4 Addresses (A Records — {domain.dns.a_records?.length || 0})
                            </span>
                            {domain.dns.a_records?.length > 0 ? (
                              <div className="mt-1.5 flex flex-wrap gap-2">
                                {domain.dns.a_records.map((ip, i) => (
                                  <span
                                    key={i}
                                    className="inline-flex items-center gap-1.5 rounded-md bg-slate-950 px-2.5 py-1 font-mono text-xs font-semibold text-cyan-300 border border-slate-800"
                                  >
                                    {ip}
                                    <button
                                      type="button"
                                      onClick={() => copyUrl(ip)}
                                      title="Copy IP"
                                      className="text-slate-500 hover:text-white transition"
                                    >
                                      <Copy className="h-3 w-3" />
                                    </button>
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <p className="text-xs italic text-slate-500 mt-1">No IPv4 A-records returned.</p>
                            )}
                          </div>

                          {/* Nameservers */}
                          <div>
                            <span className="text-[0.625rem] font-bold uppercase tracking-wider text-slate-400">
                              Authoritative Nameservers (NS Records — {domain.dns.ns_records?.length || 0})
                            </span>
                            {domain.dns.ns_records?.length > 0 ? (
                              <div className="mt-1.5 flex flex-wrap gap-2">
                                {domain.dns.ns_records.map((ns, i) => (
                                  <span
                                    key={i}
                                    className="rounded-md bg-slate-950 px-2.5 py-1 font-mono text-xs text-slate-300 border border-slate-800"
                                  >
                                    {ns}
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <p className="text-xs italic text-slate-500 mt-1">No NS records returned.</p>
                            )}
                          </div>

                          {/* MX Records */}
                          {domain.dns.mx_records?.length > 0 && (
                            <div>
                              <span className="text-[0.625rem] font-bold uppercase tracking-wider text-slate-400">
                                Mail Exchangers (MX Records)
                              </span>
                              <div className="mt-1.5 flex flex-wrap gap-2">
                                {domain.dns.mx_records.map((mx, i) => (
                                  <span
                                    key={i}
                                    className="rounded-md bg-slate-950 px-2.5 py-1 font-mono text-xs text-slate-300 border border-slate-800"
                                  >
                                    {mx}
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      ) : (
                        <div className="rounded-lg bg-slate-950 p-4 text-xs italic text-slate-500 border border-slate-800">
                          No DNS records resolved. Domain may be expired, parked, or sinkholed.
                        </div>
                      )}
                    </SocCard>
                  </div>

                  {/* Controlled Redirect Chain Resolution */}
                  {infra?.redirect_chain && (
                    <SocCard className="space-y-4">
                      <SocSectionHeader
                        icon={ArrowRightLeft}
                        title="Controlled HTTP Redirect Chain & SSRF Defense"
                        subtitle="Safe multi-hop tracer with private IP validation (SSRF) and URL shortener expansion."
                      >
                        <span className={`rounded-md px-2.5 py-1 font-mono text-xs font-semibold border ${
                          infra.redirect_chain.ssrf_blocked
                            ? 'bg-rose-500/15 text-rose-300 border-rose-500/30'
                            : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                        }`}>
                          {infra.redirect_chain.ssrf_blocked ? 'SSRF VIOLATION HALTED' : 'SSRF Safe'}
                        </span>
                      </SocSectionHeader>

                      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 font-mono text-xs">
                        <div className="rounded-lg bg-slate-950 p-3 border border-slate-800">
                          <span className="text-slate-400 text-[0.625rem] uppercase">Total Hops</span>
                          <div className="font-bold text-white text-base mt-0.5">{infra.redirect_chain.total_hops}</div>
                        </div>
                        <div className="rounded-lg bg-slate-950 p-3 border border-slate-800">
                          <span className="text-slate-400 text-[0.625rem] uppercase">Shortener</span>
                          <div className="font-bold text-cyan-300 text-base mt-0.5">
                            {infra.redirect_chain.is_shortened ? (infra.redirect_chain.shortener_provider || 'Yes') : 'Direct'}
                          </div>
                        </div>
                        <div className="rounded-lg bg-slate-950 p-3 border border-slate-800">
                          <span className="text-slate-400 text-[0.625rem] uppercase">Cross-Domain</span>
                          <div className="font-bold text-base mt-0.5">
                            {infra.redirect_chain.has_cross_domain_redirect ? (
                              <span className="text-amber-400">Yes (Domain Shift)</span>
                            ) : (
                              <span className="text-slate-400">No</span>
                            )}
                          </div>
                        </div>
                        <div className="rounded-lg bg-slate-950 p-3 border border-slate-800">
                          <span className="text-slate-400 text-[0.625rem] uppercase">Cyclic Loop</span>
                          <div className="font-bold text-base mt-0.5">
                            {infra.redirect_chain.has_redirect_loop ? (
                              <span className="text-rose-400">Loop Detected</span>
                            ) : (
                              <span className="text-emerald-400">Clean</span>
                            )}
                          </div>
                        </div>
                      </div>

                      {/* Final Destination */}
                      {infra.redirect_chain.final_url && infra.redirect_chain.final_url !== result.url && (
                        <div className="rounded-lg bg-slate-950 p-3 text-xs border border-cyan-500/30">
                          <span className="text-slate-400 font-medium">Final Unmasked URL: </span>
                          <span className="font-mono font-bold text-cyan-300 break-all">{infra.redirect_chain.final_url}</span>
                        </div>
                      )}
                    </SocCard>
                  )}
                </div>
              )}

              {/* ========================================================= */}
              {/* TAB 3: DOMAIN INTELLIGENCE & REPUTATION */}
              {/* ========================================================= */}
              {activeTab === 'tab3_domain' && (
                <div className="space-y-6 animate-in fade-in duration-200">
                  {/* Layer Header */}
                  <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl bg-slate-900/80 p-4 border border-slate-800">
                    <div className="flex items-center gap-3">
                      <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                        <Globe className="h-5 w-5" />
                      </span>
                      <div>
                        <h3 className="font-manrope text-base font-bold text-white">
                          Layer 3: Domain Intelligence, Registration & Reputation
                        </h3>
                        <p className="text-xs text-slate-400">
                          RDAP/WHOIS age verification, Newly Registered Domain (NRD) alerts, Algorithmic DGA detection, and Threat Feeds.
                        </p>
                      </div>
                    </div>
                    <span className="rounded-md bg-slate-800 px-2.5 py-1 font-mono text-xs font-semibold text-cyan-300 border border-slate-700">
                      Sub-Score: {domain?.domain_risk_score || 0} / 100
                    </span>
                  </div>

                  {/* Case A: URL is IP-based */}
                  {features?.is_ip_address ? (
                    <SocCard className="space-y-4 border-amber-500/40">
                      <SocSectionHeader
                        icon={Server}
                        iconClass="text-amber-400 bg-amber-500/10 border-amber-500/30"
                        title="IP Host Intelligence (Direct IP Address)"
                        subtitle="This target URL references a direct IP host instead of a registered domain name."
                      />
                      <div className="rounded-lg bg-amber-500/10 p-4 text-xs text-amber-300 border border-amber-500/30 space-y-1">
                        <p className="font-semibold text-amber-200">Domain Registration (WHOIS/RDAP) Not Applicable:</p>
                        <p className="text-slate-300 leading-relaxed">
                          Adversaries frequently deploy malware droppers directly onto IP addresses to bypass domain registration audits.
                          The system's Availability-Aware Engine automatically excluded the domain registration channel and dynamically renormalized the remaining active weights.
                        </p>
                      </div>
                    </SocCard>
                  ) : (
                    /* Case B: Domain WHOIS & Registration */
                    <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
                      {/* WHOIS Card */}
                      <SocCard className="space-y-3">
                        <SocSectionHeader icon={Globe} title="RDAP / WHOIS Registration Metadata" />
                        {domain?.registration?.is_data_available ? (
                          <div>
                            <SocRow label="Domain Name" value={domain.registration.domain_name} tone="cyan" />
                            <SocRow label="Accredited Registrar" value={domain.registration.registrar} truncate />
                            <SocRow label="Registrant Country" value={domain.registration.registrant_country || 'Redacted'} />
                            <SocRow label="Registration Date" value={domain.registration.creation_date} truncate />
                            <SocRow label="Expiration Date" value={domain.registration.expiration_date} truncate />
                            <SocRow label="DNSSEC Signed" value={domain.registration.dnssec_enabled ? 'Enabled' : 'Disabled'} tone={domain.registration.dnssec_enabled ? 'ok' : 'muted'} />
                            <SocRow label="Data Source" value={domain.registration.data_source?.toUpperCase()} tone="cyan" />
                          </div>
                        ) : (
                          <div className="rounded-lg bg-amber-500/10 p-3.5 text-xs text-amber-300 border border-amber-500/30">
                            WHOIS/RDAP registration data was unavailable or rate-limited. Channel weight dynamically redistributed.
                          </div>
                        )}
                      </SocCard>

                      {/* Domain Age & NRD Card */}
                      <SocCard className="space-y-3">
                        <SocSectionHeader
                          icon={Clock}
                          title="Domain Age & NRD Threat Engine"
                          subtitle="Novelty 2: Newly Registered Domain detection with mitigating trust credit."
                        />
                        {domain?.registration ? (
                          <div>
                            <SocRow
                              label="Domain Age (Days)"
                              value={domain.registration.age_days !== null ? `${domain.registration.age_days} days` : 'N/A'}
                              tone={domain.registration.is_nrd ? 'danger' : 'ok'}
                            />
                            <SocRow
                              label="Domain Age (Years)"
                              value={domain.registration.age_days !== null ? `${(domain.registration.age_days / 365).toFixed(1)} years` : 'N/A'}
                            />
                            <SocRow
                              label="Newly Registered Domain (NRD <= 30d)"
                              value={domain.registration.is_nrd ? 'FLAGGED (NRD Risk Penalty)' : 'Clean'}
                              tone={domain.registration.is_nrd ? 'danger' : 'ok'}
                            />
                            <SocRow
                              label="Young Domain (<= 90d Warning)"
                              value={domain.registration.is_young_domain ? 'YES (Recent Creation)' : 'NO'}
                              tone={domain.registration.is_young_domain ? 'warn' : 'ok'}
                            />
                            <SocRow
                              label="Privacy Protected Proxy"
                              value={domain.registration.privacy_protected ? 'YES (Redacted WHOIS)' : 'NO'}
                              tone={domain.registration.privacy_protected ? 'warn' : 'default'}
                            />
                          </div>
                        ) : (
                          <div className="rounded-lg bg-slate-950 p-4 text-xs italic text-slate-500 border border-slate-800">
                            Age calculation unavailable.
                          </div>
                        )}
                      </SocCard>
                    </div>
                  )}

                  {/* Algorithmic DGA Detection Card */}
                  {infra?.dga && (
                    <SocCard className="space-y-4">
                      <SocSectionHeader
                        icon={Cpu}
                        title="DGA (Domain Generation Algorithm) Phonetic Engine"
                        subtitle="Statistical phonetic modeling and bigram perplexity to detect botnet C2 rendezvous domains."
                      >
                        <span className={`rounded-md px-2.5 py-1 font-mono text-xs font-semibold border ${
                          infra.dga.is_dga_suspected
                            ? 'bg-rose-500/15 text-rose-300 border-rose-500/30'
                            : 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                        }`}>
                          {infra.dga.is_dga_suspected ? 'DGA SUSPECTED' : 'Natural / Benign Phonetics'}
                        </span>
                      </SocSectionHeader>

                      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 font-mono text-xs">
                        <div className="rounded-lg bg-slate-950 p-3 border border-slate-800">
                          <span className="text-slate-400 text-[0.625rem] uppercase">Domain Label</span>
                          <div className="font-bold text-cyan-300 text-sm mt-0.5 truncate" title={infra.dga.label}>
                            {infra.dga.label}
                          </div>
                          <div className="text-[0.625rem] text-slate-500 mt-1">{infra.dga.label_length} chars</div>
                        </div>
                        <div className="rounded-lg bg-slate-950 p-3 border border-slate-800">
                          <span className="text-slate-400 text-[0.625rem] uppercase">Label Entropy</span>
                          <div className="font-bold text-white text-sm mt-0.5">{infra.dga.label_entropy?.toFixed(3)}</div>
                          <div className="text-[0.625rem] text-slate-500 mt-1">Natural: 1.5 - 3.4</div>
                        </div>
                        <div className="rounded-lg bg-slate-950 p-3 border border-slate-800">
                          <span className="text-slate-400 text-[0.625rem] uppercase">Bigram Perplexity</span>
                          <div className="font-bold text-white text-sm mt-0.5">{infra.dga.bigram_perplexity?.toFixed(2)}</div>
                          <div className="text-[0.625rem] text-slate-500 mt-1">Consonants: {infra.dga.max_consecutive_consonants}</div>
                        </div>
                        <div className="rounded-lg bg-slate-950 p-3 border border-slate-800">
                          <span className="text-slate-400 text-[0.625rem] uppercase">DGA Likelihood</span>
                          <div className={`font-bold text-sm mt-0.5 ${
                            infra.dga.dga_score > 0.5 ? 'text-rose-400' : 'text-emerald-400'
                          }`}>
                            {(infra.dga.dga_score * 100).toFixed(1)}%
                          </div>
                          <div className="text-[0.625rem] text-slate-500 mt-1">Threshold: 50.0%</div>
                        </div>
                      </div>
                    </SocCard>
                  )}

                  {/* Threat Intelligence Feeds & Reputation */}
                  {domain?.reputation && (
                    <SocCard className="space-y-4">
                      <SocSectionHeader
                        icon={Radio}
                        title="External Threat Intelligence & Feed Matches"
                        subtitle="Aggregated queries against open-source threat feeds (VirusTotal, ThreatFox, Local Threat Heuristics)."
                      />
                      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                        <SocSubCard title="Threat Feed Check">
                          <div className="text-xs font-mono font-semibold text-slate-200">
                            {domain.reputation.threat_feed_checked ? 'Checked (Live Query)' : 'Local Feeds Only'}
                          </div>
                        </SocSubCard>
                        <SocSubCard title="Reputation Status">
                          <div className={`text-xs font-mono font-bold ${
                            domain.reputation.is_known_threat ? 'text-rose-400' : 'text-emerald-400'
                          }`}>
                            {domain.reputation.is_known_threat ? 'KNOWN MALICIOUS THREAT' : 'Clean on Threat Feeds'}
                          </div>
                        </SocSubCard>
                        <SocSubCard title="Threat Classification">
                          <div className="text-xs font-mono font-semibold text-cyan-300">
                            {domain.reputation.threat_type || 'None (Benign Profile)'}
                          </div>
                        </SocSubCard>
                      </div>
                    </SocCard>
                  )}
                </div>
              )}

              {/* ========================================================= */}
              {/* TAB 4: RISK ASSESSMENT & FINAL VERDICT */}
              {/* ========================================================= */}
              {activeTab === 'tab4_verdict' && risk && (
                <div className="space-y-6 animate-in fade-in duration-200">
                  {/* Executive Header with Radial Gauge & ML Comparison */}
                  <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
                    {/* Radial Score Gauge Card */}
                    <SocCard className="flex flex-col items-center justify-center p-6 text-center" glow>
                      <RadialScoreGauge score={result.score} verdict={result.verdict || result.risk_level} />
                      <div className="mt-2 text-xs text-slate-400 font-mono">
                        Engine Version: <strong className="text-slate-200">{risk.engine_version}</strong>
                      </div>
                    </SocCard>

                    {/* Dual Score Cards: Composite Score (R) & Supervised Model Probability (P) */}
                    <SocCard className="space-y-4 lg:col-span-2">
                      <SocSectionHeader
                        icon={Scale}
                        title="Consolidated Risk (R) vs ML Probability (P)"
                        subtitle="Strict epistemological separation between synthesized risk and statistical model likelihood."
                      />

                      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                        {/* Composite Risk Score (R) */}
                        <div className="rounded-xl bg-slate-950 p-4 border border-slate-800 space-y-2">
                          <div className="flex items-center justify-between">
                            <span className="text-[0.625rem] font-bold uppercase tracking-wider text-slate-400">
                              Multi-Layer Composite
                            </span>
                            <span className={`rounded-full px-2.5 py-0.5 font-mono text-[0.625rem] font-bold ${
                              SCORE_STYLES[scoreTone(result.score)].badge
                            }`}>
                              {result.verdict || result.risk_level}
                            </span>
                          </div>
                          <div className="flex items-baseline gap-1 font-mono">
                            <span className="text-3xl font-extrabold text-white">{result.score}</span>
                            <span className="text-xs text-slate-500">/ 100</span>
                          </div>
                          <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
                            <div
                              className={`h-full transition-all duration-700 ${SCORE_STYLES[scoreTone(result.score)].bar}`}
                              style={{ width: `${Math.min(result.score, 100)}%` }}
                            />
                          </div>
                          <p className="text-[0.6875rem] text-slate-400 leading-relaxed">
                            Synthesized across active channels with weights dynamically renormalized when external feeds are absent.
                          </p>
                        </div>

                        {/* Supervised ML Model Probability (P) */}
                        <div className="rounded-xl bg-slate-950 p-4 border border-slate-800 space-y-2">
                          <div className="flex items-center justify-between">
                            <span className="text-[0.625rem] font-bold uppercase tracking-wider text-slate-400">
                              Random Forest Classifier
                            </span>
                            {ml && ml.is_model_loaded && (
                              <span className={`rounded-full px-2.5 py-0.5 font-mono text-[0.625rem] font-bold ${
                                ml.predicted_label === 'malicious' ? 'bg-rose-500/20 text-rose-300' : 'bg-emerald-500/20 text-emerald-300'
                              }`}>
                                {ml.predicted_label === 'malicious' ? 'Malicious Class' : 'Legitimate Class'}
                              </span>
                            )}
                          </div>
                          {ml && ml.is_model_loaded ? (
                            <>
                              <div className="flex items-baseline gap-1 font-mono">
                                <span className="text-3xl font-extrabold text-white">
                                  {(ml.malicious_probability * 100).toFixed(1)}%
                                </span>
                                <span className="text-xs text-slate-500">Likelihood</span>
                              </div>
                              <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800">
                                <div
                                  className={`h-full transition-all duration-700 ${
                                    ml.malicious_probability >= ml.decision_threshold ? 'bg-rose-500' : 'bg-emerald-500'
                                  }`}
                                  style={{ width: `${Math.min(ml.malicious_probability * 100, 100)}%` }}
                                />
                              </div>
                              <div className="flex justify-between text-[0.6875rem] text-slate-400 font-mono">
                                <span>Latency: <strong className="text-slate-200">{ml.inference_time_ms} ms</strong></span>
                                <span>Confidence: <strong className="text-slate-200">{ml.confidence.toFixed(1)}%</strong></span>
                              </div>
                            </>
                          ) : (
                            <div className="rounded-lg bg-amber-500/10 p-3 text-xs text-amber-300">
                              ML model service is offline or loading.
                            </div>
                          )}
                        </div>
                      </div>
                    </SocCard>
                  </div>



                  {/* Chart 3: Risk Score Contribution Breakdown */}
                  <SocCard className="space-y-4">
                    <SocSectionHeader
                      icon={BarChart3}
                      title="Chart 3 — Channel Risk Contribution Breakdown"
                      subtitle="Evaluates points contributed by each intelligence channel to the overall composite risk score."
                    />
                    <RiskScoreBreakdownChart
                      channelScores={risk.channel_scores}
                      activeWeights={risk.active_weights}
                      finalScore={result.score}
                    />
                  </SocCard>

                  {/* Contributing Risk Factors & Factor Attribution (XAI) */}
                  {risk.contributing_factors?.length > 0 && (
                    <SocCard className="space-y-4">
                      <SocSectionHeader
                        icon={Layers}
                        title="Ranked Contributing Risk Factors & Factor Attribution"
                        subtitle="Decomposition of positive risk drivers and mitigating credits with concrete evidence attribution."
                      />
                      <div className="space-y-2">
                        {risk.contributing_factors.map((f, i) => {
                          const isPositive = f.impact_score > 0;
                          return (
                            <div
                              key={i}
                              className="flex items-start justify-between gap-3 rounded-lg bg-slate-950 p-3 border border-slate-800/80"
                            >
                              <div className="space-y-0.5 min-w-0">
                                <div className="flex items-center gap-2">
                                  <span className="font-semibold text-xs text-white truncate">{f.title}</span>
                                  <span className="rounded bg-slate-800 px-1.5 py-0.2 text-[0.625rem] font-mono text-cyan-300 uppercase">
                                    {f.epistemic_type}
                                  </span>
                                </div>
                                <p className="text-xs text-slate-400 leading-relaxed font-mono">{f.evidence}</p>
                              </div>
                              <span
                                className={`shrink-0 rounded px-2 py-1 font-mono text-xs font-bold ${
                                  isPositive
                                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                                    : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                                }`}
                              >
                                {isPositive ? `+${f.impact_score.toFixed(1)}` : f.impact_score.toFixed(1)} pts
                              </span>
                            </div>
                          );
                        })}
                      </div>
                    </SocCard>
                  )}

                  {/* Epistemic Evidence Breakdown (Facts vs Heuristics vs Predictions) */}
                  {risk.epistemic_breakdown && (
                    <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                      {/* Facts */}
                      <SocSubCard title="Observed Facts (Deterministic)" icon={CheckCircle2} titleClass="text-emerald-400">
                        <ul className="space-y-1 text-xs text-slate-300 font-mono">
                          {risk.epistemic_breakdown.observed_facts?.length > 0 ? (
                            risk.epistemic_breakdown.observed_facts.map((fact, idx) => (
                              <li key={idx} className="flex items-start gap-1.5">
                                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 mt-1.5 shrink-0" />
                                <span>{fact}</span>
                              </li>
                            ))
                          ) : (
                            <li className="italic text-slate-500">No raw facts recorded.</li>
                          )}
                        </ul>
                      </SocSubCard>

                      {/* Heuristics */}
                      <SocSubCard title="Heuristic Indicators (Inferences)" icon={Sliders} titleClass="text-amber-400">
                        <ul className="space-y-1 text-xs text-slate-300 font-mono">
                          {risk.epistemic_breakdown.heuristic_indicators?.length > 0 ? (
                            risk.epistemic_breakdown.heuristic_indicators.map((heur, idx) => (
                              <li key={idx} className="flex items-start gap-1.5">
                                <span className="h-1.5 w-1.5 rounded-full bg-amber-400 mt-1.5 shrink-0" />
                                <span>{heur}</span>
                              </li>
                            ))
                          ) : (
                            <li className="italic text-slate-500">No active heuristics flagged.</li>
                          )}
                        </ul>
                      </SocSubCard>

                      {/* Predictions */}
                      <SocSubCard title="Model Predictions (Statistical)" icon={BrainCircuit} titleClass="text-cyan-400">
                        <ul className="space-y-1 text-xs text-slate-300 font-mono">
                          {risk.epistemic_breakdown.model_predictions?.length > 0 ? (
                            risk.epistemic_breakdown.model_predictions.map((pred, idx) => (
                              <li key={idx} className="flex items-start gap-1.5">
                                <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 mt-1.5 shrink-0" />
                                <span>{pred}</span>
                              </li>
                            ))
                          ) : (
                            <li className="italic text-slate-500">No model predictions evaluated.</li>
                          )}
                        </ul>
                      </SocSubCard>
                    </div>
                  )}
                </div>
              )}

              {/* ========================================================= */}
              {/* 1. EVALUATED TARGET ASSET & COMPOSITE VERDICT */}
              {/* Positioned below the main webpage/tab analysis content */}
              {/* ========================================================= */}
              <SocCard className="space-y-4" glow>
                <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                  <div className="space-y-1.5 flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className={`font-mono text-[0.625rem] font-bold uppercase tracking-wider ${isDark ? 'text-cyan-400' : 'text-blue-600'}`}>
                        Evaluated Target Asset
                      </span>
                      {features?.is_ip_address && (
                        <span className={`rounded-md px-2 py-0.5 font-mono text-[0.625rem] font-bold border ${
                          isDark ? 'bg-amber-500/20 text-amber-300 border-amber-500/30' : 'bg-amber-50 text-amber-800 border-amber-200'
                        }`}>
                          Direct IP Host
                        </span>
                      )}
                    </div>

                    <h2 className="break-all font-manrope text-xl font-bold sm:text-2xl">
                      {features?.hostname || result.url}
                    </h2>

                    <div className={`flex flex-wrap items-center gap-2 text-xs ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
                      <span className="break-all font-mono font-medium">{result.url}</span>
                      <button
                        type="button"
                        onClick={() => copyUrl(result.url)}
                        className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[0.6875rem] font-medium transition cursor-pointer ${
                          isDark ? 'bg-slate-800 text-cyan-300 hover:bg-slate-700' : 'bg-slate-100 text-blue-700 hover:bg-slate-200'
                        }`}
                      >
                        {copied ? <Check className="h-3 w-3 text-emerald-500" /> : <Copy className="h-3 w-3" />}
                        <span>{copied ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                  </div>

                  {/* Score and Verdict Badges */}
                  <div className="flex flex-wrap items-center gap-4 lg:flex-col lg:items-end shrink-0">
                    <div className="flex items-center gap-3">
                      <div className="text-right">
                        <div className={`text-[0.625rem] font-bold uppercase tracking-wider ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
                          Final Verdict
                        </div>
                        <div className="mt-0.5">
                          {(() => {
                            const vInfo = getVerdictInfo(result.verdict, result.risk_level);
                            const { Icon: VIcon } = vInfo;
                            return (
                              <span className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1 text-xs font-extrabold uppercase tracking-wide ${vInfo.badge}`}>
                                <VIcon className="h-3.5 w-3.5" aria-hidden="true" />
                                {result.verdict || vInfo.label}
                              </span>
                            );
                          })()}
                        </div>
                      </div>

                      <span className={`inline-flex items-center gap-1.5 rounded-xl px-4 py-2 font-mono text-base font-extrabold shadow-sm ${
                        SCORE_STYLES[scoreTone(result.score)].badge
                      }`}>
                        {(() => {
                          const { Icon } = SCORE_STYLES[scoreTone(result.score)];
                          return <Icon className="h-4 w-4" aria-hidden="true" />;
                        })()}
                        {result.score} / 100
                      </span>
                    </div>

                    {ml && ml.is_model_loaded && (
                      <div className="flex items-center gap-2 text-xs font-mono">
                        <span className={isDark ? 'text-slate-400' : 'text-slate-500'}>ML Model:</span>
                        <span className={`font-bold uppercase ${
                          ml.predicted_label === 'malicious'
                            ? 'text-rose-500'
                            : 'text-emerald-600 dark:text-emerald-400'
                        }`}>
                          {ml.predicted_label} ({(ml.malicious_probability * 100).toFixed(1)}%)
                        </span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Natural Language Narrative Summary */}
                {result.explanation && (
                  <div className={`border-t pt-3 text-xs leading-relaxed ${
                    isDark ? 'border-slate-800 text-slate-300' : 'border-slate-200 text-slate-700'
                  }`}>
                    <p>{result.explanation}</p>
                  </div>
                )}

                {/* Layer Status Pipeline Tracker */}
                <div className={`border-t pt-3 ${isDark ? 'border-slate-800' : 'border-slate-200'}`}>
                  <LayerStatusPipeline result={result} isDark={isDark} />
                </div>
              </SocCard>

              {/* ========================================================= */}
              {/* 2. CORE RESEARCH CONTRIBUTION 3 */}
              {/* Active Channel Weights & Dynamic Renormalization */}
              {/* Positioned underneath Evaluated Target Asset */}
              {/* ========================================================= */}
              {risk && (
                <ActiveWeightsSection
                  riskAssessment={risk}
                  nominalWeights={nominalWeights}
                  isDark={isDark}
                />
              )}

            </div>
          )}

        </div>
      </div>
    </AppShell>
  </C1ThemeContext.Provider>
  );
}
