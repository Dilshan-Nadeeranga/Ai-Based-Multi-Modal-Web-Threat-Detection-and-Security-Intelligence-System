import { useState } from 'react';
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
  GitFork,
  Cpu,
  Shield,
  CornerDownRight,
  ExternalLink,
  Link2,
  BrainCircuit,
  Scale,
  Sliders,
  FileText,
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
  ExternalLink as LinkIcon
} from 'lucide-react';
import AppShell from '../../../components/AppShell.jsx';

// Color and tone helpers
const TONES = {
  danger: 'text-st-error font-bold',
  warn: 'text-amber-700 font-semibold',
  ok: 'text-emerald-700 font-medium',
  accent: 'text-st-blue-dark font-medium',
  muted: 'text-st-outline',
  default: 'text-st-ink',
};

function scoreTone(score) {
  if (score >= 60) return 'danger';
  if (score >= 25) return 'amber';
  return 'safe';
}

const SCORE_STYLES = {
  danger: {
    text: 'text-st-error',
    badge: 'bg-rose-50 text-rose-800 ring-1 ring-rose-200',
    border: 'border-rose-500',
    bar: 'bg-st-error',
    Icon: ShieldAlert,
    label: 'Malicious / High Risk'
  },
  amber: {
    text: 'text-amber-600',
    badge: 'bg-amber-50 text-amber-800 ring-1 ring-amber-200',
    border: 'border-amber-500',
    bar: 'bg-amber-500',
    Icon: AlertTriangle,
    label: 'Suspicious / Warning'
  },
  safe: {
    text: 'text-emerald-600',
    badge: 'bg-emerald-50 text-emerald-800 ring-1 ring-emerald-200',
    border: 'border-emerald-500',
    bar: 'bg-emerald-600',
    Icon: ShieldCheck,
    label: 'Benign / Safe'
  },
};

// Reusable card container
function Card({ className = '', children }) {
  return <div className={`rounded-xl bg-white p-6 shadow-sm ring-1 ring-st-container/70 ${className}`}>{children}</div>;
}

// Section Header inside cards
function SectionHeader({ icon: Icon, iconClass = 'text-st-blue-dark', title, text, children }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-4 border-b border-st-container pb-4">
      <div className="flex items-start gap-3">
        <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-st-low ${iconClass}`}>
          <Icon className="h-5 w-5" aria-hidden="true" />
        </span>
        <div>
          <h3 className="font-manrope text-lg font-semibold text-st-navy">{title}</h3>
          {text && <p className="text-xs text-st-muted">{text}</p>}
        </div>
      </div>
      {children && <div className="flex flex-wrap items-center gap-2 text-xs">{children}</div>}
    </div>
  );
}

// Small badge / chip
function Chip({ className = 'bg-st-low text-st-muted', children }) {
  return <span className={`inline-flex items-center gap-1 rounded-full px-2.5 py-1 font-mono text-[0.6875rem] font-semibold ${className}`}>{children}</span>;
}

// Inner sub-card with header and content
function SubCard({ title, icon: Icon, titleClass = 'text-st-blue-dark', badge, className = '', children }) {
  return (
    <div className={`space-y-3 rounded-lg bg-st-low/60 p-4 ring-1 ring-st-container/70 ${className}`}>
      <div className="flex items-center justify-between gap-2 border-b border-st-container/50 pb-2">
        <h4 className={`flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider ${titleClass}`}>
          {Icon && <Icon className="h-4 w-4" aria-hidden="true" />} {title}
        </h4>
        {badge}
      </div>
      {children}
    </div>
  );
}

// Key-Value row
function Row({ label, value, tone = 'default', truncate = false, tooltip }) {
  return (
    <div className="flex justify-between gap-3 border-b border-st-container/60 py-1.5 text-xs last:border-b-0" title={tooltip}>
      <span className="text-st-muted">{label}</span>
      <span className={`text-right font-mono ${TONES[tone]} ${truncate ? 'max-w-[180px] truncate' : ''}`} title={truncate ? String(value) : undefined}>
        {value !== null && value !== undefined && value !== '' ? String(value) : <span className="italic text-st-outline">N/A</span>}
      </span>
    </div>
  );
}

// Bullet list for indicators
function BulletList({ items, dotClass = 'bg-st-blue', textClass = 'text-st-ink' }) {
  if (!items || items.length === 0) return null;
  return (
    <ul className="space-y-1.5 text-xs">
      {items.map((item, idx) => (
        <li key={idx} className={`flex items-start gap-1.5 ${textClass}`}>
          <span className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${dotClass}`} />
          <span>{item}</span>
        </li>
      ))}
    </ul>
  );
}

// Sample test URLs for instant demonstration
const SAMPLE_PRESETS = [
  {
    label: 'Clean Domain',
    url: 'https://google.com',
    type: 'safe',
    desc: 'Established domain with valid SSL and clean character distribution'
  },
  {
    label: 'Commercial (Tracking Token)',
    url: 'https://incarnage.com/?srsltid=AU7gw4Xh3ZyZaUEd7vknNJwSALGGys4-rUHXNgX9HwyRGK2QXX7UpLyN',
    type: 'safe',
    desc: 'High-entropy query parameter disambiguated by base-URL entropy (FP Reduction Novelty)'
  },
  {
    label: 'PayPal Phishing Lookalike',
    url: 'http://login.paypal.verify-account.com/auth',
    type: 'danger',
    desc: 'Suspicious brand keywords, high subdomain depth, unencrypted HTTP'
  },
  {
    label: 'Malware Direct IP Host',
    url: 'http://123.9.197.209:60402/bin.sh',
    type: 'danger',
    desc: 'Direct IP host, non-standard high port 60402, shell dropper script'
  },
  {
    label: 'Shortener (Redirect Trace)',
    url: 'https://tinyurl.com/5n7v48m2',
    type: 'amber',
    desc: 'Shortened URL requiring safe SSRF-protected redirection unmasking'
  }
];

export default function UrlAnalyzer() {
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('tab1_lexical');
  const [copied, setCopied] = useState(false);

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

  // Helper flags and entities
  const features = result?.features;
  const domain = result?.domain_intelligence;
  const infra = result?.threat_infrastructure;
  const ml = result?.ml_prediction;
  const risk = result?.risk_assessment;

  // Tab definitions
  const TABS = [
    {
      id: 'tab1_lexical',
      layerNumber: 'Layer 1',
      title: 'URL Lexical Analysis',
      subtitle: '57 Features · Entropy · Obfuscation',
      icon: Fingerprint,
      badge: () => {
        if (!features) return null;
        const count = (features.suspicious_keyword_count || 0) +
                      (features.has_homoglyphs ? 1 : 0) +
                      (features.is_ip_address ? 1 : 0) +
                      (features.is_double_encoded ? 1 : 0) +
                      (features.has_at_symbol ? 1 : 0) +
                      (features.is_suspicious_tld ? 1 : 0);
        return count > 0 ? `${count} Suspicious Flags` : 'Clean Structure';
      },
      badgeClass: () => {
        if (!features) return '';
        const count = (features.suspicious_keyword_count || 0) + (features.has_homoglyphs ? 1 : 0) + (features.is_ip_address ? 1 : 0);
        return count > 0 ? 'bg-rose-100 text-rose-800' : 'bg-emerald-100 text-emerald-800';
      }
    },
    {
      id: 'tab2_dns',
      layerNumber: 'Layer 2',
      title: 'DNS & Network Analysis',
      subtitle: 'Records · Redirect Chains · DGA',
      icon: Network,
      badge: () => {
        if (!domain?.dns) return null;
        if (!domain.dns.dns_resolved) return 'NXDOMAIN / Unresolved';
        return `${domain.dns.ip_count} IP(s) Resolved`;
      },
      badgeClass: () => {
        if (!domain?.dns) return '';
        return domain.dns.dns_resolved ? 'bg-st-fixed text-st-blue-dark' : 'bg-amber-100 text-amber-800';
      }
    },
    {
      id: 'tab3_domain',
      layerNumber: 'Layer 3',
      title: 'Domain Intelligence & Reputation',
      subtitle: 'WHOIS/RDAP · Age · Threat Feeds',
      icon: Globe,
      badge: () => {
        if (features?.is_ip_address) return 'IP Host (No Domain)';
        if (!domain?.registration) return null;
        if (domain.registration.is_nrd) return 'NRD Alert (<=30d)';
        if (domain.registration.age_days !== null) return `${Math.floor(domain.registration.age_days / 365)}y Domain Age`;
        return domain.registration.data_source || 'Available';
      },
      badgeClass: () => {
        if (domain?.registration?.is_nrd || domain?.reputation?.is_known_threat) return 'bg-rose-100 text-rose-800';
        return 'bg-emerald-100 text-emerald-800';
      }
    },
    {
      id: 'tab4_verdict',
      layerNumber: 'Layer 4',
      title: 'Risk Assessment & Final Verdict',
      subtitle: 'Consolidated Score · RF Classifier · XAI',
      icon: Scale,
      badge: () => {
        if (!result) return null;
        return `Score: ${result.score}/100`;
      },
      badgeClass: () => {
        if (!result) return '';
        const tone = scoreTone(result.score);
        return SCORE_STYLES[tone].badge;
      }
    }
  ];

  return (
    <AppShell title="Threat Analysis">
      <div className="flex w-full flex-col gap-6 px-4 py-8 md:px-8">

        {/* Component Header */}
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-full bg-st-container px-2.5 py-0.5 font-mono text-[0.6875rem] font-bold uppercase tracking-wider text-st-blue-dark">
              Component C1
            </span>
            <span className="rounded-full bg-st-low px-2.5 py-0.5 text-[0.6875rem] font-semibold text-st-muted">
              4-Layer Autonomous Detection Architecture
            </span>
            <span className="rounded-full bg-emerald-50 px-2.5 py-0.5 text-[0.6875rem] font-semibold text-emerald-700 ring-1 ring-emerald-200">
              Random Forest · 57 Features · Dynamic Renormalization
            </span>
          </div>

          <h1 className="font-manrope text-2xl font-bold tracking-tight text-st-navy sm:text-3xl lg:text-4xl">
            Intelligent URL & Domain Analyzer
          </h1>
          <p className="max-w-3xl text-sm leading-relaxed text-st-muted">
            Inspect URLs across four defensive intelligence layers: Lexical Heuristics, DNS & Network Infrastructure, Domain Telemetry & Reputation, and Supervised Machine Learning with Explainable Factor Attribution.
          </p>
        </div>

        {/* URL Input Card */}
        <Card>
          <form onSubmit={handleAnalyze} className="flex flex-col gap-3">
            <div className="flex flex-col gap-3 md:flex-row">
              <div className="relative flex-1">
                <Globe className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-st-outline" aria-hidden="true" />
                <input
                  type="text"
                  aria-label="URL or domain to analyze"
                  placeholder="Enter a URL or domain (e.g. https://login.paypal.verify-account.com/auth or http://123.9.197.209:60402/bin.sh)"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  className="w-full rounded-lg bg-st-low/70 py-3.5 pl-12 pr-4 text-sm text-st-navy outline-none ring-1 ring-st-container transition placeholder:text-st-outline focus:bg-white focus:ring-2 focus:ring-st-blue-dark"
                />
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="submit"
                  disabled={loading || !urlInput.trim()}
                  className="flex flex-1 items-center justify-center gap-2 rounded-lg bg-st-navy px-6 py-3.5 text-sm font-semibold text-white shadow-md shadow-st-navy/20 transition hover:bg-st-blue-dark disabled:cursor-not-allowed disabled:opacity-50 md:flex-initial"
                >
                  {loading ? (
                    <span className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                  ) : (
                    <Search className="h-4 w-4" aria-hidden="true" />
                  )}
                  {loading ? 'Extracting 4 Layers...' : 'Analyze URL'}
                </button>

                {urlInput && (
                  <button
                    type="button"
                    onClick={() => { setUrlInput(''); setResult(null); setError(null); }}
                    className="rounded-lg bg-st-low px-4 py-3.5 text-xs font-semibold text-st-muted transition hover:bg-st-container hover:text-st-navy"
                  >
                    Clear
                  </button>
                )}
              </div>
            </div>

            {/* Quick-Test Demonstration Presets */}
            <div className="flex flex-wrap items-center gap-2 pt-1 text-xs text-st-muted">
              <span className="font-semibold text-st-navy">Quick Demonstration Presets:</span>
              {SAMPLE_PRESETS.map((preset) => (
                <button
                  key={preset.label}
                  type="button"
                  onClick={() => handleAnalyze(null, preset.url)}
                  disabled={loading}
                  title={preset.desc}
                  className={`flex items-center gap-1.5 rounded-md px-2.5 py-1 text-[0.75rem] font-medium transition ring-1 ${
                    preset.type === 'danger'
                      ? 'bg-rose-50 text-rose-700 ring-rose-200 hover:bg-rose-100'
                      : preset.type === 'amber'
                      ? 'bg-amber-50 text-amber-700 ring-amber-200 hover:bg-amber-100'
                      : 'bg-emerald-50 text-emerald-700 ring-emerald-200 hover:bg-emerald-100'
                  }`}
                >
                  {preset.type === 'danger' && <AlertTriangle className="h-3 w-3" />}
                  {preset.type === 'safe' && <CheckCircle2 className="h-3 w-3" />}
                  {preset.type === 'amber' && <Link2 className="h-3 w-3" />}
                  <span>{preset.label}</span>
                </button>
              ))}
            </div>
          </form>
        </Card>

        {/* Loading State Skeleton */}
        {loading && (
          <Card className="flex flex-col items-center justify-center py-12 text-center">
            <div className="relative mb-4">
              <div className="h-16 w-16 animate-spin rounded-full border-4 border-st-container border-t-st-blue-dark" />
              <Layers className="absolute left-1/2 top-1/2 h-6 w-6 -translate-x-1/2 -translate-y-1/2 text-st-blue-dark" />
            </div>
            <h3 className="font-manrope text-lg font-bold text-st-navy">Executing Multi-Layer Cybersecurity Pipeline</h3>
            <p className="mt-1 max-w-md text-xs text-st-muted">
              Parsing 57 lexical features, performing DNS socket lookups, interrogating RDAP/WHOIS registry, tracing redirect hops, and running Random Forest inference...
            </p>
          </Card>
        )}

        {/* Error Alert */}
        {error && !loading && (
          <div role="alert" className="flex items-center gap-3 rounded-lg bg-rose-50 p-4 text-sm text-rose-800 ring-1 ring-rose-200">
            <ShieldAlert className="h-5 w-5 shrink-0 text-rose-600" aria-hidden="true" />
            <div className="flex-1">
              <p className="font-semibold">Analysis Failed</p>
              <p className="text-xs text-rose-700">{error}</p>
            </div>
          </div>
        )}

        {/* Initial Empty State Preview (Before Analysis) */}
        {!result && !loading && !error && (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-bold uppercase tracking-wider text-st-muted">Four-Layer Threat Architecture Overview</h2>
              <span className="text-xs text-st-outline">Select a preset above or submit a URL to inspect all layers</span>
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
              {TABS.map((tab, idx) => {
                const Icon = tab.icon;
                return (
                  <div key={tab.id} className="flex flex-col justify-between rounded-xl bg-white p-5 shadow-sm ring-1 ring-st-container/70">
                    <div>
                      <div className="flex items-center justify-between">
                        <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-st-fixed text-st-blue-dark">
                          <Icon className="h-5 w-5" aria-hidden="true" />
                        </span>
                        <span className="rounded bg-st-low px-2 py-0.5 font-mono text-[0.625rem] font-bold uppercase text-st-outline">
                          Layer {idx + 1}
                        </span>
                      </div>
                      <h3 className="mt-3 font-manrope text-base font-bold text-st-navy">{tab.title}</h3>
                      <p className="mt-1 text-xs leading-relaxed text-st-muted">{tab.subtitle}</p>
                    </div>

                    <div className="mt-4 border-t border-st-container/60 pt-3 text-[0.6875rem] text-st-outline">
                      {idx === 0 && 'Extracts 57 canonical features, token entropy, punycode, and homoglyph spoofs.'}
                      {idx === 1 && 'Interrogates A, AAAA, MX, NS, TXT records, fast-flux DNS, and SSRF-safe hops.'}
                      {idx === 2 && 'Inspects RDAP/WHOIS age, newly registered domains (NRDs), and threat feeds.'}
                      {idx === 3 && 'Calibrated Random Forest classifier with explainable factor attribution.'}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Analyzed Results Display */}
        {result && (
          <div className="space-y-6">

            {/* Top Analysis Verdict Banner */}
            <Card className="border-l-4 border-l-st-blue-dark">
              <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                <div className="min-w-0 flex-1 space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-[0.6875rem] font-bold uppercase tracking-wider text-st-outline">Analyzed Target</span>
                    {features?.scheme && (
                      <span className={`inline-flex items-center gap-1 rounded px-2 py-0.5 font-mono text-[0.625rem] font-bold uppercase ${
                        features.scheme === 'https' ? 'bg-emerald-100 text-emerald-800' : 'bg-amber-100 text-amber-800'
                      }`}>
                        {features.scheme === 'https' ? <Lock className="h-2.5 w-2.5" /> : <Unlock className="h-2.5 w-2.5" />}
                        {features.scheme}
                      </span>
                    )}
                    {features?.is_ip_address && (
                      <span className="rounded bg-amber-100 px-2 py-0.5 font-mono text-[0.625rem] font-bold text-amber-800">
                        Direct IP Host ({features.ip_type})
                      </span>
                    )}
                  </div>

                  <h2 className="break-all font-manrope text-xl font-bold text-st-navy sm:text-2xl">
                    {features?.hostname || result.url}
                  </h2>

                  <div className="flex flex-wrap items-center gap-2 text-xs text-st-muted">
                    <span className="break-all font-mono text-st-ink">{result.url}</span>
                    <button
                      type="button"
                      onClick={() => copyUrl(result.url)}
                      className="inline-flex items-center gap-1 rounded bg-st-low px-1.5 py-0.5 text-[0.6875rem] font-medium text-st-blue-dark hover:bg-st-container"
                    >
                      {copied ? <Check className="h-3 w-3 text-emerald-600" /> : <Copy className="h-3 w-3" />}
                      <span>{copied ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                </div>

                {/* Score and Verdict Badges */}
                <div className="flex flex-wrap items-center gap-4 lg:flex-col lg:items-end">
                  <div className="flex items-center gap-3">
                    <div className="text-right">
                      <div className="text-[0.6875rem] uppercase text-st-muted">Final Verdict</div>
                      <div className="font-manrope text-lg font-bold text-st-navy">
                        {result.risk_level || result.risk_assessment?.classification || 'Assessed'}
                      </div>
                    </div>
                    <span className={`inline-flex items-center gap-1.5 rounded-full px-4 py-2 text-sm font-bold shadow-sm ${
                      SCORE_STYLES[scoreTone(result.score)].badge
                    }`}>
                      {(() => {
                        const { Icon } = SCORE_STYLES[scoreTone(result.score)];
                        return <Icon className="h-4 w-4" aria-hidden="true" />;
                      })()}
                      {result.score}/100
                    </span>
                  </div>

                  {ml && ml.is_model_loaded && (
                    <div className="flex items-center gap-2 text-xs">
                      <span className="text-st-muted">ML Model:</span>
                      <span className={`font-mono font-bold uppercase ${
                        ml.predicted_label === 'malicious' ? 'text-st-error' : 'text-emerald-700'
                      }`}>
                        {ml.predicted_label} ({(ml.malicious_probability * 100).toFixed(1)}%)
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {/* Natural Language Explanation */}
              {result.explanation && (
                <div className="mt-4 border-t border-st-container pt-3">
                  <p className="text-xs leading-relaxed text-st-ink sm:text-sm">
                    {result.explanation}
                  </p>
                </div>
              )}
            </Card>

            {/* 4-LAYER TAB NAVIGATION BAR */}
            <div className="border-b border-st-container">
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                {TABS.map((tab) => {
                  const Icon = tab.icon;
                  const isActive = activeTab === tab.id;
                  const badgeText = tab.badge();
                  const badgeClass = tab.badgeClass();

                  return (
                    <button
                      key={tab.id}
                      type="button"
                      onClick={() => setActiveTab(tab.id)}
                      className={`relative flex flex-col items-start rounded-t-xl p-3.5 text-left transition ${
                        isActive
                          ? 'bg-white shadow-sm ring-1 ring-st-container/80'
                          : 'bg-st-low/50 hover:bg-st-low text-st-muted hover:text-st-navy'
                      }`}
                    >
                      <div className="flex w-full items-center justify-between gap-1">
                        <span className={`flex h-7 w-7 items-center justify-center rounded-md ${
                          isActive ? 'bg-st-navy text-white' : 'bg-st-container text-st-blue-dark'
                        }`}>
                          <Icon className="h-4 w-4" aria-hidden="true" />
                        </span>
                        <span className="font-mono text-[0.625rem] font-bold uppercase tracking-wider text-st-outline">
                          {tab.layerNumber}
                        </span>
                      </div>

                      <div className="mt-2 w-full">
                        <h3 className={`font-manrope text-xs font-bold leading-tight sm:text-sm ${
                          isActive ? 'text-st-navy' : 'text-st-ink'
                        }`}>
                          {tab.title}
                        </h3>
                        <p className="hidden truncate text-[0.6875rem] text-st-muted sm:block">
                          {tab.subtitle}
                        </p>
                      </div>

                      {badgeText && (
                        <div className="mt-2">
                          <span className={`inline-block rounded-full px-2 py-0.5 font-mono text-[0.625rem] font-bold ${badgeClass}`}>
                            {badgeText}
                          </span>
                        </div>
                      )}

                      {/* Active Tab Underline Accent */}
                      {isActive && (
                        <div className="absolute -bottom-px left-0 right-0 h-0.5 bg-st-blue-dark" />
                      )}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* TAB CONTENT PANELS */}
            <div className="space-y-6">

              {/* ========================================================= */}
              {/* TAB 1: URL LEXICAL ANALYSIS */}
              {/* ========================================================= */}
              {activeTab === 'tab1_lexical' && features && (
                <div className="space-y-6 st-fade-in">

                  {/* Layer Summary Header */}
                  <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg bg-st-low/80 p-4 ring-1 ring-st-container">
                    <div className="flex items-center gap-3">
                      <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-st-fixed text-st-blue-dark">
                        <Fingerprint className="h-5 w-5" />
                      </span>
                      <div>
                        <h3 className="font-manrope text-base font-bold text-st-navy">Layer 1: URL Lexical & Structural Heuristics</h3>
                        <p className="text-xs text-st-muted">57 canonical features evaluated without external network dependency.</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Chip className="bg-st-fixed text-st-navy">Feature Space: 57 Dims</Chip>
                      {features.has_tracking_param && (
                        <Chip className="bg-emerald-100 text-emerald-800">Tracking Disambiguated</Chip>
                      )}
                    </div>
                  </div>

                  {/* Parsed URL Components Anatomy Card */}
                  <Card className="space-y-4">
                    <SectionHeader
                      icon={Code}
                      title="Parsed URL Structural Breakdown"
                      text="Anatomical decomposition of the submitted URI according to RFC 3986 specifications."
                    />

                    <div className="grid grid-cols-1 gap-2 rounded-lg bg-st-low p-3 font-mono text-xs sm:grid-cols-2 lg:grid-cols-4">
                      <div className="rounded bg-white p-2.5 ring-1 ring-st-container">
                        <div className="text-[0.6875rem] font-bold text-st-outline uppercase">Scheme</div>
                        <div className="mt-1 font-semibold text-st-blue-dark">{features.scheme || 'N/A'}</div>
                      </div>
                      <div className="rounded bg-white p-2.5 ring-1 ring-st-container">
                        <div className="text-[0.6875rem] font-bold text-st-outline uppercase">Subdomain</div>
                        <div className="mt-1 truncate font-semibold text-st-ink" title={features.subdomain || 'None'}>
                          {features.subdomain || <span className="text-st-outline italic">None</span>}
                        </div>
                      </div>
                      <div className="rounded bg-white p-2.5 ring-1 ring-st-container">
                        <div className="text-[0.6875rem] font-bold text-st-outline uppercase">Registered Domain (Apex)</div>
                        <div className="mt-1 truncate font-semibold text-st-navy" title={features.registered_domain || 'N/A'}>
                          {features.registered_domain || 'N/A'}
                        </div>
                      </div>
                      <div className="rounded bg-white p-2.5 ring-1 ring-st-container">
                        <div className="text-[0.6875rem] font-bold text-st-outline uppercase">Top-Level Domain (TLD)</div>
                        <div className="mt-1 font-semibold text-st-blue-dark">
                          .{features.tld || 'N/A'} {features.is_suspicious_tld && <span className="text-rose-600">(Risky TLD)</span>}
                        </div>
                      </div>
                      <div className="rounded bg-white p-2.5 ring-1 ring-st-container">
                        <div className="text-[0.6875rem] font-bold text-st-outline uppercase">Port</div>
                        <div className="mt-1 font-semibold text-st-ink">
                          {features.port || (features.scheme === 'https' ? '443 (Default)' : '80 (Default)')}
                          {!features.is_standard_port && <span className="ml-1 text-st-error font-bold">(Non-Standard)</span>}
                        </div>
                      </div>
                      <div className="rounded bg-white p-2.5 ring-1 ring-st-container">
                        <div className="text-[0.6875rem] font-bold text-st-outline uppercase">Path Depth</div>
                        <div className="mt-1 truncate font-semibold text-st-ink" title={features.path || '/'}>
                          {features.path || '/'} (Depth: {features.path_depth})
                        </div>
                      </div>
                      <div className="rounded bg-white p-2.5 ring-1 ring-st-container sm:col-span-2">
                        <div className="text-[0.6875rem] font-bold text-st-outline uppercase">Query String Parameters</div>
                        <div className="mt-1 truncate font-semibold text-st-ink" title={features.query || 'None'}>
                          {features.query ? `${features.num_query_params} param(s): ${features.query}` : <span className="text-st-outline italic">None</span>}
                        </div>
                      </div>
                    </div>
                  </Card>

                  {/* 3 Core Metric Cards: Lengths, Math/Entropy, Obfuscation */}
                  <div className="grid grid-cols-1 gap-6 md:grid-cols-3">

                    {/* Card 1: Lengths & Structural Ratios */}
                    <Card className="space-y-3">
                      <div className="flex items-center gap-2 border-b border-st-container pb-3">
                        <Globe className="h-4 w-4 text-st-blue-dark" />
                        <h4 className="font-manrope text-sm font-bold text-st-navy">Lengths & Structural Ratios</h4>
                      </div>
                      <div>
                        <Row label="Total URL Length" value={`${features.url_length} chars`} tone={features.url_length > 100 ? 'warn' : 'accent'} />
                        <Row label="Hostname Length" value={`${features.hostname_length} chars`} tone="accent" />
                        <Row label="Path Length" value={`${features.path_length} chars`} tone="accent" />
                        <Row label="Path-to-URL Ratio" value={`${(features.path_to_url_ratio * 100).toFixed(1)}%`} tone="accent" />
                        <Row label="Subdomain Count" value={features.num_subdomains} tone={features.num_subdomains >= 3 ? 'warn' : 'default'} />
                        <Row label="Domain Hierarchy Depth" value={features.domain_depth} tone="accent" />
                        <Row label="Dots Count" value={`${features.num_dots} (Host: ${features.num_dots_hostname})`} />
                        <Row label="Hyphens Count" value={`${features.num_hyphens} (Host: ${features.num_hyphens_hostname})`} />
                      </div>
                    </Card>

                    {/* Card 2: Shannon Entropy & Math Metrics */}
                    <Card className="space-y-3">
                      <div className="flex items-center gap-2 border-b border-st-container pb-3">
                        <BarChart3 className="h-4 w-4 text-st-blue-dark" />
                        <h4 className="font-manrope text-sm font-bold text-st-navy">Entropy & Math Metrics</h4>
                      </div>
                      <div>
                        <Row label="Global URL Entropy" value={`${features.url_entropy.toFixed(3)} bits/char`} tone={features.url_entropy > 4.5 ? 'warn' : 'accent'} />
                        <Row
                          label="Base URL Entropy"
                          value={`${features.base_url_entropy?.toFixed(3) || 'N/A'} bits/char`}
                          tone="accent"
                          tooltip="Entropy of Scheme + Host + Path excluding Query. Isolates marketing tokens to eliminate false positives."
                        />
                        <Row label="Hostname Entropy" value={`${features.hostname_entropy.toFixed(3)} bits/char`} tone="accent" />
                        <Row label="Path Entropy" value={`${features.path_entropy.toFixed(3)} bits/char`} tone="default" />
                        <Row label="Digit Ratio" value={`${(features.digit_ratio * 100).toFixed(1)}%`} tone={features.digit_ratio > 0.3 ? 'warn' : 'default'} />
                        <Row label="Max Consecutive Digits" value={features.max_consecutive_digits} tone={features.max_consecutive_digits >= 5 ? 'warn' : 'default'} />
                        <Row label="Max Char Repetition" value={features.max_character_repetition} tone={features.has_excessive_repetition ? 'warn' : 'default'} />
                        <Row label="Special Characters" value={features.num_special_chars} tone="default" />
                      </div>
                    </Card>

                    {/* Card 3: Security & Obfuscation Heuristics */}
                    <Card className="space-y-3">
                      <div className="flex items-center gap-2 border-b border-st-container pb-3">
                        <Key className="h-4 w-4 text-st-blue-dark" />
                        <h4 className="font-manrope text-sm font-bold text-st-navy">Obfuscation & Spoofing Flags</h4>
                      </div>
                      <div>
                        <Row
                          label="IP Address Host"
                          value={features.is_ip_address ? `YES (${features.ip_type})` : 'NO'}
                          tone={features.is_ip_address ? 'danger' : 'ok'}
                        />
                        <Row
                          label="Homoglyph Spoofing"
                          value={features.has_homoglyphs ? 'DETECTED' : 'Clean'}
                          tone={features.has_homoglyphs ? 'danger' : 'ok'}
                        />
                        <Row
                          label="Punycode (xn--)"
                          value={features.is_punycode ? 'YES' : 'NO'}
                          tone={features.is_punycode ? 'warn' : 'ok'}
                        />
                        <Row
                          label="Double Percent Encoded"
                          value={features.is_double_encoded ? 'YES' : 'NO'}
                          tone={features.is_double_encoded ? 'danger' : 'ok'}
                        />
                        <Row
                          label="Userinfo Delimiter (@)"
                          value={features.has_at_symbol ? 'YES' : 'NO'}
                          tone={features.has_at_symbol ? 'danger' : 'ok'}
                        />
                        <Row
                          label="Hex/Octal Obfuscation"
                          value={features.has_hex_obfuscation ? 'DETECTED' : 'NO'}
                          tone={features.has_hex_obfuscation ? 'warn' : 'ok'}
                        />
                        <Row
                          label="URL Shortener Detected"
                          value={features.is_shortened_url ? 'YES' : 'NO'}
                          tone={features.is_shortened_url ? 'warn' : 'default'}
                        />
                        <Row
                          label="Tracking Token Disambiguated"
                          value={features.has_tracking_param ? 'YES (Marketing)' : 'NO'}
                          tone={features.has_tracking_param ? 'ok' : 'default'}
                        />
                      </div>
                    </Card>
                  </div>

                  {/* Suspicious Keywords & Marketing Disambiguation Banner */}
                  <div className="grid grid-cols-1 gap-6 md:grid-cols-2">

                    {/* Suspicious Keywords */}
                    <Card className="space-y-3">
                      <div className="flex items-center justify-between border-b border-st-container pb-3">
                        <h4 className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-rose-800">
                          <AlertTriangle className="h-4 w-4 text-rose-600" /> Suspicious Brand / Security Keywords
                        </h4>
                        <Chip className={features.has_suspicious_keyword ? 'bg-rose-100 text-rose-800' : 'bg-emerald-100 text-emerald-800'}>
                          {features.suspicious_keyword_count} Matched
                        </Chip>
                      </div>

                      {features.suspicious_keywords_found && features.suspicious_keywords_found.length > 0 ? (
                        <div className="space-y-2">
                          <p className="text-xs text-st-muted">The following target strings were detected in the URL path or subdomain:</p>
                          <div className="flex flex-wrap gap-1.5">
                            {features.suspicious_keywords_found.map((kw, i) => (
                              <span key={i} className="rounded-md bg-rose-50 px-2.5 py-1 font-mono text-xs font-bold text-rose-800 ring-1 ring-rose-200">
                                {kw}
                              </span>
                            ))}
                          </div>
                        </div>
                      ) : (
                        <p className="p-3 text-center text-xs italic text-st-outline">
                          No suspicious phishing keywords (e.g., login, verify, banking, update) were found.
                        </p>
                      )}
                    </Card>

                    {/* Marketing & Tracking Token Disambiguation (Novelty Showcase) */}
                    <Card className="space-y-3">
                      <div className="flex items-center justify-between border-b border-st-container pb-3">
                        <h4 className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-emerald-800">
                          <CheckCircle2 className="h-4 w-4 text-emerald-600" /> Commercial Query Disambiguation (Novelty)
                        </h4>
                        <Chip className={features.has_tracking_param ? 'bg-emerald-100 text-emerald-800' : 'bg-st-low text-st-muted'}>
                          {features.has_tracking_param ? 'Active Protection' : 'None Detected'}
                        </Chip>
                      </div>

                      {features.has_tracking_param ? (
                        <div className="space-y-2 text-xs text-emerald-900">
                          <p className="leading-relaxed">
                            Legitimate advertising tokens (e.g., <code className="font-mono font-bold">srsltid</code>, <code className="font-mono font-bold">utm_*</code>, or <code className="font-mono font-bold">gclid</code>) were detected in the query parameters.
                          </p>
                          <div className="rounded-lg bg-emerald-50/70 p-3 text-[0.6875rem] ring-1 ring-emerald-200">
                            <strong>Research Impact:</strong> Standard research models flag marketing tokens as high-entropy payload obfuscation (&gt;98% false positive rate). Component C1 isolates <code className="font-mono">base_url_entropy</code> ({features.base_url_entropy?.toFixed(3)}) to prevent false alerts.
                          </div>
                        </div>
                      ) : (
                        <p className="p-3 text-center text-xs italic text-st-outline">
                          Standard query string. No high-entropy marketing or affiliate tracking parameters detected.
                        </p>
                      )}
                    </Card>
                  </div>

                  {/* Homoglyph Spoof Details (If any) */}
                  {features.has_homoglyphs && features.homoglyph_details && features.homoglyph_details.length > 0 && (
                    <Card className="space-y-3 border-l-4 border-l-rose-500 bg-rose-50/40">
                      <h4 className="flex items-center gap-2 font-manrope text-sm font-bold text-rose-900">
                        <ShieldAlert className="h-4 w-4 text-rose-600" /> Homoglyph / Internationalized Lookalike Spoofing Detected
                      </h4>
                      <div className="space-y-2">
                        {features.homoglyph_details.map((h, i) => (
                          <div key={i} className="flex items-center justify-between rounded bg-white p-2.5 text-xs ring-1 ring-rose-200">
                            <span className="font-mono font-bold text-rose-800">Character &apos;{h.char}&apos; (U+{h.codepoint})</span>
                            <span className="text-st-muted">Spoofs Latin character: <strong className="font-mono text-st-navy">&apos;{h.target}&apos;</strong></span>
                          </div>
                        ))}
                      </div>
                    </Card>
                  )}

                </div>
              )}

              {/* ========================================================= */}
              {/* TAB 2: DNS & NETWORK ANALYSIS */}
              {/* ========================================================= */}
              {activeTab === 'tab2_dns' && (
                <div className="space-y-6 st-fade-in">

                  {/* Layer Summary Header */}
                  <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg bg-st-low/80 p-4 ring-1 ring-st-container">
                    <div className="flex items-center gap-3">
                      <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-st-fixed text-st-blue-dark">
                        <Network className="h-5 w-5" />
                      </span>
                      <div>
                        <h3 className="font-manrope text-base font-bold text-st-navy">Layer 2: DNS & Network Threat Infrastructure</h3>
                        <p className="text-xs text-st-muted">Real-time DNS records, Fast-Flux detection, DGA analysis, and SSRF-safe redirect tracing.</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Chip className={domain?.dns?.dns_resolved ? 'bg-emerald-100 text-emerald-800' : 'bg-rose-100 text-rose-800'}>
                        {domain?.dns?.dns_resolved ? 'DNS Resolved' : 'Resolution Failed'}
                      </Chip>
                      <Chip className="bg-emerald-100 text-emerald-800">
                        SSRF Protected
                      </Chip>
                    </div>
                  </div>

                  {/* DNS Records & Infrastructure Grid */}
                  <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">

                    {/* DNS Health & Behavioral Signals */}
                    <Card className="space-y-3">
                      <SectionHeader icon={Server} title="DNS Resolution & Health" />
                      {domain?.dns ? (
                        <div>
                          <Row
                            label="DNS Resolution Status"
                            value={domain.dns.dns_resolved ? 'Resolved Successfully' : 'NXDOMAIN / Unresolved'}
                            tone={domain.dns.dns_resolved ? 'ok' : 'danger'}
                          />
                          <Row label="Resolved A-Records (IPv4)" value={`${domain.dns.ip_count || 0} IP(s)`} tone="accent" />
                          <Row label="Minimum Record TTL" value={domain.dns.min_ttl ? `${domain.dns.min_ttl}s` : 'N/A'} tone={domain.dns.min_ttl && domain.dns.min_ttl < 60 ? 'warn' : 'default'} />
                          <Row
                            label="Fast-Flux Threat Pattern"
                            value={domain.dns.is_fast_flux ? 'DETECTED (High Turnover)' : 'Clean'}
                            tone={domain.dns.is_fast_flux ? 'danger' : 'ok'}
                          />
                          <Row
                            label="Dynamic DNS (DDNS) Provider"
                            value={domain.dns.is_dynamic_dns ? 'YES (Free DDNS Host)' : 'NO'}
                            tone={domain.dns.is_dynamic_dns ? 'warn' : 'ok'}
                          />
                          <Row
                            label="Private IP Resolution Leak"
                            value={domain.dns.is_private_ip_resolved ? 'LEAK (RFC1918 Private IP)' : 'Clean (Public IP)'}
                            tone={domain.dns.is_private_ip_resolved ? 'danger' : 'ok'}
                          />
                          <Row
                            label="Mail Exchange (MX) Configured"
                            value={domain.dns.has_mx_records ? 'Configured' : 'None'}
                            tone={domain.dns.has_mx_records ? 'ok' : 'muted'}
                          />
                          <Row
                            label="SPF Email Authentication"
                            value={domain.dns.has_spf ? 'Configured' : 'Missing'}
                            tone={domain.dns.has_spf ? 'ok' : 'muted'}
                          />
                        </div>
                      ) : (
                        <div className="rounded-lg bg-amber-50 p-4 text-xs text-amber-800">
                          DNS resolution data is unavailable for this input.
                        </div>
                      )}
                    </Card>

                    {/* DNS Records Inspector (A, AAAA, MX, NS, TXT) */}
                    <Card className="space-y-3 lg:col-span-2">
                      <SectionHeader icon={Database} title="Discovered DNS Resource Records" />

                      {domain?.dns && domain.dns.dns_resolved ? (
                        <div className="space-y-3">

                          {/* A Records */}
                          <div className="space-y-1">
                            <span className="text-[0.6875rem] font-bold uppercase tracking-wider text-st-outline">
                              IPv4 Addresses (A Records — {domain.dns.a_records?.length || 0})
                            </span>
                            {domain.dns.a_records && domain.dns.a_records.length > 0 ? (
                              <div className="flex flex-wrap gap-1.5">
                                {domain.dns.a_records.map((ip, i) => (
                                  <span key={i} className="inline-flex items-center gap-1 rounded bg-st-low px-2 py-1 font-mono text-xs font-semibold text-st-blue-dark ring-1 ring-st-container">
                                    {ip}
                                    <button
                                      type="button"
                                      onClick={() => copyUrl(ip)}
                                      title="Copy IP"
                                      className="text-st-outline hover:text-st-navy"
                                    >
                                      <Copy className="h-2.5 w-2.5" />
                                    </button>
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <p className="text-xs italic text-st-outline">No IPv4 A-records returned.</p>
                            )}
                          </div>

                          {/* Nameservers (NS) */}
                          <div className="space-y-1 pt-2">
                            <span className="text-[0.6875rem] font-bold uppercase tracking-wider text-st-outline">
                              Authoritative Nameservers (NS Records — {domain.dns.ns_records?.length || 0})
                            </span>
                            {domain.dns.ns_records && domain.dns.ns_records.length > 0 ? (
                              <div className="flex flex-wrap gap-1.5">
                                {domain.dns.ns_records.map((ns, i) => (
                                  <span key={i} className="rounded bg-st-low px-2 py-1 font-mono text-xs text-st-navy ring-1 ring-st-container">
                                    {ns}
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <p className="text-xs italic text-st-outline">No authoritative nameservers listed.</p>
                            )}
                          </div>

                          {/* Mail Exchange (MX) & TXT Records */}
                          <div className="grid grid-cols-1 gap-3 pt-2 sm:grid-cols-2">
                            <div>
                              <span className="text-[0.6875rem] font-bold uppercase tracking-wider text-st-outline">
                                Mail Servers (MX — {domain.dns.mx_records?.length || 0})
                              </span>
                              {domain.dns.mx_records && domain.dns.mx_records.length > 0 ? (
                                <ul className="mt-1 space-y-1 font-mono text-xs text-st-ink">
                                  {domain.dns.mx_records.slice(0, 3).map((mx, i) => (
                                    <li key={i} className="truncate rounded bg-st-low p-1.5 ring-1 ring-st-container/60" title={mx}>{mx}</li>
                                  ))}
                                </ul>
                              ) : (
                                <p className="mt-1 text-xs italic text-st-outline">No MX records configured.</p>
                              )}
                            </div>

                            <div>
                              <span className="text-[0.6875rem] font-bold uppercase tracking-wider text-st-outline">
                                Domain Verification & TXT Records ({domain.dns.txt_records?.length || 0})
                              </span>
                              {domain.dns.txt_records && domain.dns.txt_records.length > 0 ? (
                                <ul className="mt-1 space-y-1 font-mono text-[0.6875rem] text-st-ink">
                                  {domain.dns.txt_records.slice(0, 2).map((txt, i) => (
                                    <li key={i} className="truncate rounded bg-st-low p-1.5 ring-1 ring-st-container/60" title={txt}>{txt}</li>
                                  ))}
                                  {domain.dns.txt_records.length > 2 && (
                                    <li className="text-[0.625rem] italic text-st-outline">+{domain.dns.txt_records.length - 2} more verification records</li>
                                  )}
                                </ul>
                              ) : (
                                <p className="mt-1 text-xs italic text-st-outline">No TXT records present.</p>
                              )}
                            </div>
                          </div>

                        </div>
                      ) : (
                        <div className="rounded-lg bg-amber-50 p-4 text-xs text-amber-800">
                          <p className="font-semibold">DNS Lookup Returned No Records or Failed</p>
                          <p className="mt-1 text-[0.6875rem]">The domain may be expired, not yet registered, or using an offline DNS provider.</p>
                        </div>
                      )}
                    </Card>

                  </div>

                  {/* Safe Redirection Chain & SSRF Boundary Tracer */}
                  {infra?.redirect_chain && (
                    <Card className="space-y-4">
                      <SectionHeader
                        icon={GitFork}
                        title="Connection & Redirection Chain Tracer"
                        text="Passive redirect follower with strict Server-Side Request Forgery (SSRF) boundary validation."
                      >
                        <Chip className="bg-emerald-100 text-emerald-800">
                          <Shield className="h-3 w-3" /> SSRF Boundary Enforced
                        </Chip>
                      </SectionHeader>

                      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
                        <div className="rounded-lg bg-st-low p-3 ring-1 ring-st-container">
                          <div className="text-[0.6875rem] font-bold uppercase text-st-outline">Redirect Status</div>
                          <div className="mt-1 font-semibold text-st-navy">
                            {infra.redirect_chain.is_redirected ? `${infra.redirect_chain.total_hops} Hop(s) Observed` : 'Direct Connection'}
                          </div>
                        </div>

                        <div className="rounded-lg bg-st-low p-3 ring-1 ring-st-container">
                          <div className="text-[0.6875rem] font-bold uppercase text-st-outline">Shortener Provider</div>
                          <div className="mt-1 font-semibold text-st-ink">
                            {infra.redirect_chain.is_shortened ? (infra.redirect_chain.shortener_provider || 'Shortened URL') : 'Direct URL'}
                          </div>
                        </div>

                        <div className="rounded-lg bg-st-low p-3 ring-1 ring-st-container">
                          <div className="text-[0.6875rem] font-bold uppercase text-st-outline">Cross-Domain Pivot</div>
                          <div className="mt-1 font-semibold text-st-ink">
                            {infra.redirect_chain.destination_domain_changed ? (
                              <span className="text-amber-700 font-bold">YES (Pivoted to new domain)</span>
                            ) : (
                              <span className="text-emerald-700">NO (Same Domain)</span>
                            )}
                          </div>
                        </div>

                        <div className="rounded-lg bg-st-low p-3 ring-1 ring-st-container">
                          <div className="text-[0.6875rem] font-bold uppercase text-st-outline">SSRF Firewall Status</div>
                          <div className="mt-1 font-semibold text-st-ink">
                            {infra.redirect_chain.ssrf_blocked ? (
                              <span className="text-st-error font-bold">BLOCKED (Private Subnet Probe)</span>
                            ) : (
                              <span className="text-emerald-700">Clean Public Target</span>
                            )}
                          </div>
                        </div>
                      </div>

                      {/* Visual Hop Trace Timeline */}
                      <div className="space-y-2">
                        <span className="text-[0.6875rem] font-bold uppercase tracking-wider text-st-outline">
                          Observed Hop Route ({infra.redirect_chain.chain_hops?.length || 0})
                        </span>

                        {infra.redirect_chain.chain_hops && infra.redirect_chain.chain_hops.length > 0 ? (
                          <div className="space-y-2">
                            {infra.redirect_chain.chain_hops.map((hop, index) => (
                              <div key={index} className="flex flex-col justify-between gap-2 rounded-lg bg-st-low p-3 text-xs ring-1 ring-st-container sm:flex-row sm:items-center">
                                <div className="flex items-center gap-2">
                                  <span className="flex h-6 w-6 items-center justify-center rounded bg-st-navy font-mono text-[0.6875rem] font-bold text-white">
                                    {hop.hop_number}
                                  </span>
                                  <div className="min-w-0">
                                    <div className="truncate font-mono font-bold text-st-navy" title={hop.url}>
                                      {hop.domain}
                                    </div>
                                    <div className="truncate font-mono text-[0.6875rem] text-st-muted" title={hop.url}>
                                      {hop.url}
                                    </div>
                                  </div>
                                </div>

                                <div className="flex items-center gap-2 text-right">
                                  {hop.resolved_ip && (
                                    <span className="rounded bg-white px-2 py-0.5 font-mono text-[0.625rem] text-st-outline ring-1 ring-st-container">
                                      {hop.resolved_ip}
                                    </span>
                                  )}
                                  <span className={`rounded px-2 py-0.5 font-mono text-[0.6875rem] font-bold ${
                                    hop.status_code >= 300 && hop.status_code < 400
                                      ? 'bg-amber-100 text-amber-800'
                                      : hop.status_code >= 200 && hop.status_code < 300
                                      ? 'bg-emerald-100 text-emerald-800'
                                      : 'bg-rose-100 text-rose-800'
                                  }`}>
                                    HTTP {hop.status_code}
                                  </span>
                                </div>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <div className="rounded-lg bg-st-low/50 p-4 text-center text-xs italic text-st-outline">
                            Direct connection established without redirection hops.
                          </div>
                        )}
                      </div>

                      {/* Final Destination */}
                      {infra.redirect_chain.final_url && infra.redirect_chain.final_url !== result.url && (
                        <div className="rounded-lg bg-st-fixed/60 p-3 text-xs">
                          <span className="text-st-muted">Final Unmasked URL: </span>
                          <span className="font-mono font-bold text-st-navy break-all">{infra.redirect_chain.final_url}</span>
                        </div>
                      )}
                    </Card>
                  )}

                  {/* DGA (Domain Generation Algorithm) Infrastructure Card */}
                  {infra?.dga && (
                    <Card className="space-y-4">
                      <SectionHeader
                        icon={Cpu}
                        title="DGA (Domain Generation Algorithm) Analysis"
                        text="Statistical phonetic modeling and bigram perplexity to detect malware-generated domains."
                      >
                        <Chip className={infra.dga.is_dga_suspected ? 'bg-rose-100 text-rose-800' : 'bg-emerald-100 text-emerald-800'}>
                          {infra.dga.is_dga_suspected ? 'DGA Suspected' : 'Natural / Benign Phonetics'}
                        </Chip>
                      </SectionHeader>

                      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
                        <SubCard title="Analyzed Label" titleClass="text-st-navy">
                          <div className="font-mono text-sm font-bold text-st-blue-dark truncate" title={infra.dga.label}>
                            {infra.dga.label}
                          </div>
                          <div className="text-[0.6875rem] text-st-muted">Length: {infra.dga.label_length} chars</div>
                        </SubCard>

                        <SubCard title="Label Entropy" titleClass="text-st-navy">
                          <div className="font-mono text-sm font-bold text-st-ink">
                            {infra.dga.label_entropy?.toFixed(3)} bits/char
                          </div>
                          <div className="text-[0.6875rem] text-st-muted">Natural range: 1.5 - 3.4</div>
                        </SubCard>

                        <SubCard title="Bigram Perplexity" titleClass="text-st-navy">
                          <div className="font-mono text-sm font-bold text-st-ink">
                            {infra.dga.bigram_perplexity?.toFixed(2)}
                          </div>
                          <div className="text-[0.6875rem] text-st-muted">Consonant run: {infra.dga.max_consecutive_consonants}</div>
                        </SubCard>

                        <SubCard title="DGA Score" titleClass="text-st-navy">
                          <div className={`font-mono text-sm font-bold ${
                            infra.dga.dga_score > 0.5 ? 'text-st-error' : 'text-emerald-700'
                          }`}>
                            {(infra.dga.dga_score * 100).toFixed(1)}%
                          </div>
                          <div className="text-[0.6875rem] text-st-muted">Threshold: 50.0%</div>
                        </SubCard>
                      </div>

                      {infra.dga.dga_family_hint && (
                        <div className="rounded-lg bg-amber-50 p-3 text-xs text-amber-800">
                          <strong>Pattern Family Hint:</strong> {infra.dga.dga_family_hint}
                        </div>
                      )}
                    </Card>
                  )}

                </div>
              )}

              {/* ========================================================= */}
              {/* TAB 3: DOMAIN INTELLIGENCE & REPUTATION */}
              {/* ========================================================= */}
              {activeTab === 'tab3_domain' && (
                <div className="space-y-6 st-fade-in">

                  {/* Layer Summary Header */}
                  <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg bg-st-low/80 p-4 ring-1 ring-st-container">
                    <div className="flex items-center gap-3">
                      <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-st-fixed text-st-blue-dark">
                        <Globe className="h-5 w-5" />
                      </span>
                      <div>
                        <h3 className="font-manrope text-base font-bold text-st-navy">Layer 3: Domain Intelligence, Registration & Reputation</h3>
                        <p className="text-xs text-st-muted">RDAP/WHOIS age verification, Newly Registered Domain (NRD) alerts, SSL transport, and threat feed feeds.</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Chip className="bg-st-fixed text-st-navy">
                        Sub-Score: {domain?.domain_risk_score || 0}/100
                      </Chip>
                    </div>
                  </div>

                  {/* Domain Registration OR Direct IP Host Details */}
                  {features?.is_ip_address ? (
                    /* Case A: URL is IP-based */
                    <Card className="space-y-4 border-l-4 border-l-amber-500 bg-amber-50/20">
                      <SectionHeader
                        icon={Server}
                        iconClass="text-amber-600"
                        title="IP Host Intelligence (Direct IP Address)"
                        text="This target URL references a direct IP host instead of a registered domain name."
                      />

                      <div className="space-y-3">
                        <div className="rounded-lg bg-amber-50 p-4 text-xs text-amber-900 ring-1 ring-amber-200">
                          <p className="font-semibold">Domain Registration (WHOIS/RDAP) Not Applicable:</p>
                          <p className="mt-1">
                            Attackers frequently deploy phishing and malware droppers directly onto IP addresses (or compromised IoT devices) to evade domain registration audits and domain reputation blacklists.
                          </p>
                        </div>

                        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
                          <SubCard title="Host IP" titleClass="text-st-navy">
                            <div className="font-mono text-sm font-bold text-st-blue-dark">{features.hostname}</div>
                            <div className="text-[0.6875rem] text-st-muted">Format: {features.ip_type}</div>
                          </SubCard>

                          <SubCard title="Network Scope" titleClass="text-st-navy">
                            <div className="font-mono text-sm font-bold text-st-ink">
                              {features.is_private_ip ? 'Private Subnet (RFC1918)' : 'Public Internet'}
                            </div>
                            <div className="text-[0.6875rem] text-st-muted">Routable: {features.is_private_ip ? 'No' : 'Yes'}</div>
                          </SubCard>

                          <SubCard title="Port Allocation" titleClass="text-st-navy">
                            <div className="font-mono text-sm font-bold text-st-ink">
                              Port {features.port || (features.scheme === 'https' ? '443' : '80')}
                            </div>
                            <div className="text-[0.6875rem] text-st-muted">{features.is_standard_port ? 'Standard Web Port' : 'High / Non-Standard Port'}</div>
                          </SubCard>

                          <SubCard title="Host Reputation" titleClass="text-st-navy">
                            <div className="font-mono text-sm font-bold text-amber-700">Elevated Risk Flag</div>
                            <div className="text-[0.6875rem] text-st-muted">Heuristic penalty applied</div>
                          </SubCard>
                        </div>
                      </div>
                    </Card>
                  ) : (
                    /* Case B: Standard Domain Name */
                    <Card className="space-y-4">
                      <SectionHeader
                        icon={Clock}
                        title="Domain Registration & Ownership (WHOIS / RDAP)"
                        text="Historical domain age, registrar credibility, and Newly Registered Domain (NRD) analysis."
                      >
                        {domain?.registration?.is_nrd && (
                          <span className="inline-flex items-center gap-1 rounded-full bg-rose-100 px-3 py-1 font-mono text-xs font-bold text-rose-800">
                            <AlertTriangle className="h-3.5 w-3.5" /> NRD Alert (Age &le; 30 Days)
                          </span>
                        )}
                      </SectionHeader>

                      {domain?.registration ? (
                        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
                          <SubCard title="Domain Age & Lifecycle" titleClass="text-emerald-700">
                            <div>
                              <Row
                                label="Domain Age"
                                value={domain.registration.age_days !== null
                                  ? `${domain.registration.age_days} days (~${(domain.registration.age_days / 365).toFixed(1)} yrs)`
                                  : 'Data Unavailable'}
                                tone={domain.registration.is_nrd ? 'danger' : 'ok'}
                              />
                              <Row
                                label="NRD Status (<= 30 Days)"
                                value={domain.registration.is_nrd ? 'CRITICAL (Newly Registered)' : 'Established'}
                                tone={domain.registration.is_nrd ? 'danger' : 'ok'}
                              />
                              <Row
                                label="Days Until Expiration"
                                value={domain.registration.days_until_expiration !== null
                                  ? `${domain.registration.days_until_expiration} days`
                                  : 'Unknown'}
                                tone={domain.registration.days_until_expiration && domain.registration.days_until_expiration < 30 ? 'warn' : 'default'}
                              />
                              <Row
                                label="DNSSEC Enabled"
                                value={domain.registration.dnssec_enabled ? 'Signed' : 'Unsigned'}
                                tone={domain.registration.dnssec_enabled ? 'ok' : 'muted'}
                              />
                            </div>
                          </SubCard>

                          <SubCard title="Registrar & Registry" titleClass="text-st-blue-dark">
                            <div>
                              <Row label="Registrar Organization" value={domain.registration.registrar || 'Protected / Unknown'} truncate />
                              <Row label="Registrant Country" value={domain.registration.registrant_country || 'Redacted'} />
                              <Row label="Privacy Proxy Active" value={domain.registration.privacy_protected ? 'Yes (WhoisGuard)' : 'No / Direct'} />
                              <Row label="Telemetry Protocol" value={String(domain.registration.data_source || 'RDAP').toUpperCase()} tone="accent" />
                            </div>
                          </SubCard>

                          <SubCard title="Registration Timestamps" titleClass="text-st-navy-2">
                            <div>
                              <Row label="Creation Date" value={domain.registration.creation_date ? domain.registration.creation_date.split('T')[0] : 'N/A'} />
                              <Row label="Last Updated" value={domain.registration.updated_date ? domain.registration.updated_date.split('T')[0] : 'N/A'} />
                              <Row label="Expiration Date" value={domain.registration.expiration_date ? domain.registration.expiration_date.split('T')[0] : 'N/A'} />
                            </div>
                          </SubCard>
                        </div>
                      ) : (
                        <div className="rounded-lg bg-amber-50 p-4 text-xs text-amber-800">
                          WHOIS / RDAP telemetry could not be resolved for this apex domain.
                        </div>
                      )}
                    </Card>
                  )}

                  {/* SSL / TLS Transport Security Card */}
                  <Card className="space-y-4">
                    <SectionHeader icon={Lock} title="SSL / TLS Transport Encryption Status" />

                    <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                      <div className="rounded-lg bg-st-low p-3 ring-1 ring-st-container">
                        <div className="text-[0.6875rem] font-bold uppercase text-st-outline">Transport Protocol</div>
                        <div className="mt-1 flex items-center gap-1.5 font-mono text-sm font-bold">
                          {features?.scheme === 'https' ? (
                            <>
                              <Lock className="h-4 w-4 text-emerald-600" />
                              <span className="text-emerald-700">HTTPS (TLS Encrypted)</span>
                            </>
                          ) : (
                            <>
                              <Unlock className="h-4 w-4 text-rose-600" />
                              <span className="text-st-error">HTTP (Unencrypted Plaintext)</span>
                            </>
                          )}
                        </div>
                      </div>

                      <div className="rounded-lg bg-st-low p-3 ring-1 ring-st-container">
                        <div className="text-[0.6875rem] font-bold uppercase text-st-outline">Connection Port</div>
                        <div className="mt-1 font-mono text-sm font-bold text-st-navy">
                          Port {features?.port || (features?.scheme === 'https' ? '443' : '80')}
                          {features?.is_standard_port ? (
                            <span className="ml-1 text-xs text-emerald-700 font-normal">(Standard)</span>
                          ) : (
                            <span className="ml-1 text-xs text-rose-600 font-normal">(Non-Standard)</span>
                          )}
                        </div>
                      </div>

                      <div className="rounded-lg bg-st-low p-3 ring-1 ring-st-container">
                        <div className="text-[0.6875rem] font-bold uppercase text-st-outline">Transport Risk Level</div>
                        <div className="mt-1 font-mono text-sm font-bold">
                          {features?.scheme === 'https' ? (
                            <span className="text-emerald-700">Secure Protocol</span>
                          ) : (
                            <span className="text-rose-700">Vulnerable to MitM Interception</span>
                          )}
                        </div>
                      </div>
                    </div>
                  </Card>

                  {/* Threat Intelligence Feeds & Community Reputation */}
                  <Card className="space-y-4">
                    <SectionHeader icon={Shield} title="Threat Intelligence Feeds & Reputation" />

                    <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
                      <SubCard title="Reputation Engine Status" titleClass="text-st-navy">
                        <div>
                          <Row
                            label="Threat Feed Check"
                            value={domain?.reputation?.is_known_threat ? 'MATCH FOUND (Malicious)' : 'Clean / No Match'}
                            tone={domain?.reputation?.is_known_threat ? 'danger' : 'ok'}
                          />
                          <Row label="Feed Source" value={domain?.reputation?.reputation_source || 'abuse.ch URLhaus & PhishTank'} />
                          <Row label="Threat Type Tag" value={domain?.reputation?.threat_type || 'None'} tone="accent" />
                          <Row label="Intelligence Confidence" value={`${(domain?.reputation?.confidence_score || 0) * 100}%`} />
                        </div>
                      </SubCard>

                      <SubCard title="Observed Domain Indicators" titleClass="text-st-navy">
                        {domain?.domain_risk_indicators && domain.domain_risk_indicators.length > 0 ? (
                          <BulletList items={domain.domain_risk_indicators} dotClass="bg-amber-500" textClass="text-amber-900" />
                        ) : (
                          <p className="p-3 text-center text-xs italic text-st-outline">
                            No negative reputation strikes observed across threat feeds or DNS heuristics.
                          </p>
                        )}
                      </SubCard>
                    </div>
                  </Card>

                </div>
              )}

              {/* ========================================================= */}
              {/* TAB 4: RISK ASSESSMENT & FINAL VERDICT */}
              {/* ========================================================= */}
              {activeTab === 'tab4_verdict' && (
                <div className="space-y-6 st-fade-in">

                  {/* Layer Summary Header */}
                  <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg bg-st-low/80 p-4 ring-1 ring-st-container">
                    <div className="flex items-center gap-3">
                      <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-st-fixed text-st-blue-dark">
                        <Scale className="h-5 w-5" />
                      </span>
                      <div>
                        <h3 className="font-manrope text-base font-bold text-st-navy">Layer 4: Risk Assessment & Final Verdict</h3>
                        <p className="text-xs text-st-muted">Synthesized Multi-Channel Risk Engine and Supervised Random Forest Classifier with XAI Factor Attribution.</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Chip className="bg-st-fixed text-st-navy">
                        Engine: {risk?.engine_version || 'c1-explainable-risk-v1.0.0'}
                      </Chip>
                      <Chip className="bg-st-fixed text-st-navy">
                        Classifier: Random Forest (57 Feat.)
                      </Chip>
                    </div>
                  </div>

                  {/* Dual Score Cards: Consolidated Risk Score (R) & Supervised Model Probability (P) */}
                  <div className="grid grid-cols-1 gap-6 md:grid-cols-2">

                    {/* Left: Consolidated Multi-Layer Score (R) */}
                    <Card className="space-y-4">
                      <div className="flex items-center justify-between border-b border-st-container pb-3">
                        <div>
                          <div className="text-[0.6875rem] font-bold uppercase tracking-wider text-st-outline">Multi-Layer Composite</div>
                          <h4 className="font-manrope text-base font-bold text-st-navy">Consolidated Risk Score (R)</h4>
                        </div>
                        <span className={`rounded-full px-3 py-1 font-mono text-xs font-bold ${
                          SCORE_STYLES[scoreTone(result.score)].badge
                        }`}>
                          {result.risk_level}
                        </span>
                      </div>

                      <div className="flex items-baseline justify-between">
                        <div className={`font-mono text-4xl font-extrabold ${SCORE_STYLES[scoreTone(result.score)].text}`}>
                          {result.score} <span className="text-lg font-normal text-st-muted">/ 100</span>
                        </div>
                        <span className="font-mono text-xs text-st-muted">Range: 0 (Safe) – 100 (Critical)</span>
                      </div>

                      <div className="h-2.5 w-full overflow-hidden rounded-full bg-st-container">
                        <div
                          className={`h-full transition-all duration-700 ${SCORE_STYLES[scoreTone(result.score)].bar}`}
                          style={{ width: `${Math.min(result.score, 100)}%` }}
                        />
                      </div>

                      <p className="text-xs text-st-muted leading-relaxed">
                        Synthesized across active evidentiary channels with weights dynamically renormalized when WHOIS, DNS or external feeds are unavailable.
                      </p>
                    </Card>

                    {/* Right: Supervised ML Model Probability (P) */}
                    <Card className="space-y-4">
                      <div className="flex items-center justify-between border-b border-st-container pb-3">
                        <div>
                          <div className="text-[0.6875rem] font-bold uppercase tracking-wider text-st-outline">Supervised Machine Learning</div>
                          <h4 className="font-manrope text-base font-bold text-st-navy">Random Forest Classifier (P)</h4>
                        </div>
                        {ml && ml.is_model_loaded && (
                          <span className={`rounded-full px-3 py-1 font-mono text-xs font-bold ${
                            ml.predicted_label === 'malicious' ? 'bg-rose-100 text-rose-800' : 'bg-emerald-100 text-emerald-800'
                          }`}>
                            {ml.predicted_label === 'malicious' ? 'Classified Malicious' : 'Classified Legitimate'}
                          </span>
                        )}
                      </div>

                      {ml && ml.is_model_loaded ? (
                        <>
                          <div className="flex items-baseline justify-between">
                            <div className="font-mono text-4xl font-extrabold text-st-navy">
                              {(ml.malicious_probability * 100).toFixed(1)}%
                              <span className="text-xs font-normal text-st-muted ml-2">Malicious Likelihood</span>
                            </div>
                            <span className="font-mono text-xs text-st-muted">Threshold: {(ml.decision_threshold * 100).toFixed(0)}%</span>
                          </div>

                          <div className="h-2.5 w-full overflow-hidden rounded-full bg-st-container">
                            <div
                              className={`h-full transition-all duration-700 ${
                                ml.malicious_probability >= ml.decision_threshold ? 'bg-st-error' : 'bg-emerald-600'
                              }`}
                              style={{ width: `${Math.min(ml.malicious_probability * 100, 100)}%` }}
                            />
                          </div>

                          <div className="flex justify-between text-xs text-st-muted">
                            <span>Inference Latency: <strong className="font-mono text-st-navy">{ml.inference_time_ms} ms</strong></span>
                            <span>Model Confidence: <strong className="font-mono text-st-navy">{ml.confidence.toFixed(1)}%</strong></span>
                            <span>Feature Space: <strong className="font-mono text-st-navy">{ml.feature_count} Dims</strong></span>
                          </div>
                        </>
                      ) : (
                        <div className="rounded-lg bg-amber-50 p-4 text-xs text-amber-800">
                          ML Model service is offline or loading.
                        </div>
                      )}
                    </Card>

                  </div>

                  {/* Multi-Layer Findings Synthesis (Summary of All 3 Layers) */}
                  <Card className="space-y-4">
                    <SectionHeader
                      icon={Layers}
                      title="Multi-Layer Findings Synthesis"
                      text="Executive technical summary synthesized across Layers 1, 2, and 3."
                    />

                    <div className="grid grid-cols-1 gap-4 md:grid-cols-3">

                      {/* Layer 1 Summary */}
                      <div className="rounded-lg bg-st-low p-4 ring-1 ring-st-container space-y-2">
                        <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-st-blue-dark">
                          <Fingerprint className="h-4 w-4" /> Layer 1 · Lexical
                        </div>
                        <p className="text-xs text-st-ink leading-relaxed">
                          {features?.url_length} chars, base entropy {features?.base_url_entropy?.toFixed(2) || 'N/A'}.
                          {features?.suspicious_keyword_count > 0
                            ? ` ${features.suspicious_keyword_count} suspicious keyword(s) detected.`
                            : ' No suspicious brand keywords found.'}
                          {features?.has_tracking_param && ' Marketing parameters disambiguated.'}
                          {features?.has_homoglyphs && ' Homoglyph character lookalike spoofing flagged.'}
                        </p>
                      </div>

                      {/* Layer 2 Summary */}
                      <div className="rounded-lg bg-st-low p-4 ring-1 ring-st-container space-y-2">
                        <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-st-blue-dark">
                          <Network className="h-4 w-4" /> Layer 2 · DNS & Network
                        </div>
                        <p className="text-xs text-st-ink leading-relaxed">
                          {domain?.dns?.dns_resolved
                            ? `Resolved to ${domain.dns.ip_count} IP(s).`
                            : 'DNS lookup returned unresolved or NXDOMAIN.'}
                          {infra?.redirect_chain?.is_shortened && ' Shortened redirect target uncloaked.'}
                          {infra?.dga?.is_dga_suspected ? ' DGA algorithm suspected.' : ' Natural linguistic phonetics.'}
                        </p>
                      </div>

                      {/* Layer 3 Summary */}
                      <div className="rounded-lg bg-st-low p-4 ring-1 ring-st-container space-y-2">
                        <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-st-blue-dark">
                          <Globe className="h-4 w-4" /> Layer 3 · Domain & Reputation
                        </div>
                        <p className="text-xs text-st-ink leading-relaxed">
                          {features?.is_ip_address
                            ? 'Direct IP address destination. WHOIS not applicable.'
                            : domain?.registration?.is_nrd
                            ? 'Newly registered domain (<= 30 days).'
                            : `Established domain (${domain?.registration?.age_days ? Math.floor(domain.registration.age_days / 365) + ' years old' : 'Age verified'}).`}
                          {domain?.reputation?.is_known_threat ? ' Known threat feed match found.' : ' Clean reputation on threat feeds.'}
                        </p>
                      </div>

                    </div>
                  </Card>

                  {/* Contributing Risk Factors & Factor Attribution (XAI) */}
                  {risk?.contributing_factors && risk.contributing_factors.length > 0 && (
                    <Card className="space-y-4">
                      <SectionHeader
                        icon={FileText}
                        title="Explainable Factor Attribution (XAI)"
                        text="Decomposition of positive risk drivers and mitigating factors with their epistemological classification."
                      />

                      <div className="space-y-2">
                        {risk.contributing_factors.map((factor, idx) => {
                          const isMitigating = factor.impact_score < 0;
                          return (
                            <div key={idx} className="flex flex-col justify-between gap-2 rounded-lg bg-st-low p-3.5 text-xs ring-1 ring-st-container sm:flex-row sm:items-center">
                              <div className="flex-1 space-y-1">
                                <div className="flex flex-wrap items-center gap-2">
                                  <span className={`font-bold ${isMitigating ? 'text-emerald-700' : 'text-st-navy'}`}>
                                    {factor.title}
                                  </span>
                                  <span className={`rounded px-2 py-0.5 font-mono text-[0.625rem] font-bold uppercase tracking-wider ${
                                    factor.epistemic_type === 'fact'
                                      ? 'bg-st-fixed text-st-navy'
                                      : factor.epistemic_type === 'heuristic'
                                      ? 'bg-amber-100 text-amber-800'
                                      : 'bg-violet-100 text-violet-800'
                                  }`}>
                                    [{factor.epistemic_type}]
                                  </span>
                                  <span className="font-mono text-[0.625rem] text-st-outline">
                                    {factor.category}
                                  </span>
                                </div>
                                <p className="text-xs text-st-muted leading-relaxed">
                                  {factor.evidence}
                                </p>
                              </div>

                              <div className="flex shrink-0 items-center justify-between sm:flex-col sm:items-end">
                                <span className={`font-mono text-sm font-bold ${isMitigating ? 'text-emerald-700' : 'text-st-error'}`}>
                                  {factor.impact_score > 0 ? `+${factor.impact_score.toFixed(1)}` : factor.impact_score.toFixed(1)} pts
                                </span>
                                <span className="text-[0.625rem] text-st-outline uppercase">
                                  Confidence: {factor.confidence}
                                </span>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </Card>
                  )}

                  {/* Active Channel Weights & Dynamic Renormalization */}
                  {risk?.active_weights && (
                    <Card className="space-y-4">
                      <SectionHeader
                        icon={Sliders}
                        title="Active Channel Weights & Dynamic Renormalization"
                        text="Weights dynamically redistribute across available channels to eliminate false penalties when external registries fail."
                      />

                      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 xl:grid-cols-8">
                        {[
                          { key: 'lexical_structural', label: 'Lexical / Structural' },
                          { key: 'entropy_obfuscation', label: 'Entropy & Evasion' },
                          { key: 'homoglyph_lookalike', label: 'Homoglyph Lookalike' },
                          { key: 'domain_registration', label: 'Domain Age & NRD' },
                          { key: 'dns_reputation', label: 'DNS & Threat Feeds' },
                          { key: 'dga', label: 'DGA Algorithmic' },
                          { key: 'shortener_redirect', label: 'Redirects & SSRF' },
                          { key: 'machine_learning', label: 'Machine Learning' },
                        ].map((ch) => {
                          const weight = risk.active_weights[ch.key] || 0;
                          const score = risk.channel_scores?.[ch.key] || 0;
                          const isActive = weight > 0;

                          return (
                            <div key={ch.key} className={`space-y-1.5 rounded-lg p-3 text-xs ring-1 ring-st-container ${
                              isActive ? 'bg-st-low' : 'bg-st-low/40 opacity-50'
                            }`}>
                              <div className="font-semibold text-st-navy text-[0.6875rem] truncate" title={ch.label}>{ch.label}</div>
                              <div className="flex justify-between text-[0.6875rem]">
                                <span className="text-st-muted">Weight</span>
                                <span className="font-mono font-bold text-st-blue-dark">{isActive ? `${(weight * 100).toFixed(0)}%` : 'Excluded'}</span>
                              </div>
                              <div className="flex justify-between text-[0.6875rem]">
                                <span className="text-st-muted">Score</span>
                                <span className="font-mono font-bold text-st-ink">{score.toFixed(0)}</span>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </Card>
                  )}

                  {/* Recommended Security Actions */}
                  <Card className="space-y-3">
                    <h4 className="flex items-center gap-2 font-manrope text-sm font-bold text-st-navy">
                      <Zap className="h-4 w-4 text-st-blue-dark" /> Recommended Defensive Action
                    </h4>
                    <div className={`rounded-lg p-4 text-xs ring-1 ${
                      result.score >= 60
                        ? 'bg-rose-50 text-rose-900 ring-rose-200'
                        : result.score >= 25
                        ? 'bg-amber-50 text-amber-900 ring-amber-200'
                        : 'bg-emerald-50 text-emerald-900 ring-emerald-200'
                    }`}>
                      {result.score >= 60 ? (
                        <p className="leading-relaxed">
                          <strong>Immediate Action Recommended:</strong> Block this URL and domain across email gateways, web proxies, and DNS firewalls. Target exhibits strong indicators of malicious intent (phishing, C2 dropper, or high-risk lookalike).
                        </p>
                      ) : result.score >= 25 ? (
                        <p className="leading-relaxed">
                          <strong>Caution Advised:</strong> Suspicious characteristics observed (e.g., brand keywords or new domain age). Do not enter passwords or sensitive personal details unless identity is verified out-of-band.
                        </p>
                      ) : (
                        <p className="leading-relaxed">
                          <strong>Standard Browsing Permitted:</strong> No malicious indicators detected across all 4 defense layers. The domain exhibits natural lexical distributions and established registration history.
                        </p>
                      )}
                    </div>
                  </Card>

                </div>
              )}

            </div>

            {/* Collapsible Raw Multi-Layer JSON Inspector */}
            <Card>
              <details className="group">
                <summary className="flex cursor-pointer items-center justify-between text-xs font-bold uppercase tracking-wider text-st-muted hover:text-st-navy">
                  <span className="flex items-center gap-2">
                    <Terminal className="h-4 w-4 text-st-blue-dark" />
                    Inspect Complete Multi-Layer JSON Payload
                  </span>
                  <span className="font-mono text-[0.6875rem] text-st-outline">Click to Expand</span>
                </summary>
                <div className="mt-3">
                  <pre className="max-h-80 overflow-x-auto rounded-lg bg-st-ink p-4 font-mono text-xs text-st-fixed">
                    {JSON.stringify(result, null, 2)}
                  </pre>
                </div>
              </details>
            </Card>

          </div>
        )}

      </div>
    </AppShell>
  );
}
