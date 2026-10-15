import { useState } from 'react';
import axios from 'axios';
import { Search, ShieldAlert, ShieldCheck, AlertTriangle, Globe, Code, Key, Terminal, GitFork, Cpu, Shield, CornerDownRight, ExternalLink, Link2, BrainCircuit, Scale, Sliders, FileText, CheckCircle2, Info, Network, Fingerprint } from 'lucide-react';
import AppShell from '../../../components/AppShell.jsx';

const TONES = {
  danger: 'text-st-error font-bold',
  warn: 'text-amber-700 font-semibold',
  ok: 'text-emerald-700',
  accent: 'text-st-blue-dark',
  muted: 'text-st-outline',
  default: 'text-st-ink',
};

const LAYERS = [
  { icon: Fingerprint, title: 'Lexical & Structural', text: 'URL length, entropy, homoglyphs, punycode and suspicious keywords.' },
  { icon: Globe, title: 'Domain Intelligence', text: 'Registration age, RDAP, DNS records and reputation feeds.' },
  { icon: Network, title: 'Threat Infrastructure', text: 'DGA patterns, URL shorteners and safe redirect-chain tracing.' },
  { icon: BrainCircuit, title: 'Machine Learning', text: 'Supervised classifier probability with explainable risk scoring.' },
];

function scoreTone(score) {
  if (score >= 75) return 'danger';
  if (score >= 50) return 'orange';
  if (score >= 25) return 'amber';
  return 'safe';
}

const SCORE_STYLES = {
  danger: { text: 'text-st-error', badge: 'bg-st-error-bg text-st-error-ink', Icon: ShieldAlert },
  orange: { text: 'text-orange-600', badge: 'bg-orange-100 text-orange-800', Icon: AlertTriangle },
  amber: { text: 'text-amber-600', badge: 'bg-amber-100 text-amber-800', Icon: AlertTriangle },
  safe: { text: 'text-emerald-600', badge: 'bg-emerald-100 text-emerald-800', Icon: ShieldCheck },
};

function Card({ className = '', children }) {
  return <div className={`rounded-xl bg-white p-6 shadow-sm ring-1 ring-st-container/60 ${className}`}>{children}</div>;
}

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

function Chip({ className = 'bg-st-low text-st-muted', children }) {
  return <span className={`rounded-full px-2.5 py-1 font-mono text-[0.6875rem] font-semibold ${className}`}>{children}</span>;
}

function SubCard({ title, icon: Icon, titleClass = 'text-st-blue-dark', badge, className = '', children }) {
  return (
    <div className={`space-y-3 rounded-lg bg-st-low/70 p-4 ring-1 ring-st-container/70 ${className}`}>
      <div className="flex items-center justify-between gap-2">
        <h4 className={`flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider ${titleClass}`}>
          {Icon && <Icon className="h-4 w-4" aria-hidden="true" />} {title}
        </h4>
        {badge}
      </div>
      {children}
    </div>
  );
}

function Row({ label, value, tone = 'default', truncate = false }) {
  return (
    <div className="flex justify-between gap-3 border-b border-st-container/80 py-1.5 text-xs last:border-b-0">
      <span className="text-st-muted">{label}</span>
      <span className={`text-right font-mono ${TONES[tone]} ${truncate ? 'max-w-[150px] truncate' : ''}`} title={truncate ? String(value) : undefined}>
        {value}
      </span>
    </div>
  );
}

function BulletList({ items, dotClass, textClass = 'text-st-ink' }) {
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

export default function UrlAnalyzer() {
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleAnalyze = async (e) => {
    e.preventDefault();
    if (!urlInput.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      // Call C1 directly or via Gateway
      const gatewayUrl = import.meta.env.VITE_GATEWAY_URL || 'http://localhost:5000';
      const c1Url = import.meta.env.VITE_C1_URL || 'http://localhost:8001';

      let response;
      try {
        response = await axios.post(`${c1Url}/analyze-url`, { url: urlInput });
      } catch {
        // Fallback to gateway if direct C1 fails
        const gwRes = await axios.post(`${gatewayUrl}/api/analyze`, { url: urlInput });
        response = { data: gwRes.data.component_results.c1_url_domain };
      }

      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to analyze URL');
    } finally {
      setLoading(false);
    }
  };

  const getRiskBadge = (level, score) => {
    const { badge, Icon } = SCORE_STYLES[scoreTone(score)];
    return (
      <span className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 text-sm font-bold ${badge}`}>
        <Icon className="h-4 w-4" aria-hidden="true" /> {level} ({score}/100)
      </span>
    );
  };

  const risk = result?.risk_assessment;
  const domain = result?.domain_intelligence;
  const infra = result?.threat_infrastructure;
  const ml = result?.ml_prediction;

  return (
    <AppShell title="Threat Analysis">
      <div className="flex w-full flex-col gap-8 px-4 py-8 md:px-8">

        {/* Header */}
        <div className="flex flex-col gap-1">
          <span className="w-fit rounded-full bg-st-container px-2 py-0.5 text-[0.6875rem] font-bold uppercase tracking-widest text-st-blue-dark">
            Component C1
          </span>
          <h1 className="font-manrope text-[1.75rem] font-bold tracking-tight text-st-navy lg:text-4xl">Intelligent URL & Domain Analyzer</h1>
          <p className="max-w-3xl text-base text-st-muted">
            Multi-layer URL and domain intelligence: lexical features, domain registration, threat infrastructure and machine learning, combined into one explainable risk score.
          </p>
        </div>

        {/* Input Form */}
        <Card>
          <form onSubmit={handleAnalyze} className="flex flex-col gap-3 md:flex-row">
            <div className="relative flex-1">
              <Globe className="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-st-outline" aria-hidden="true" />
              <input
                type="text"
                aria-label="URL or domain to analyze"
                placeholder="Enter a URL or domain (e.g. http://login.paypal.verify-account.com/auth)"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                className="w-full rounded-lg bg-st-low/60 py-3 pl-12 pr-4 text-sm text-st-navy outline-none ring-1 ring-st-container transition placeholder:text-st-outline focus:bg-white focus:ring-2 focus:ring-st-blue-dark"
              />
            </div>
            <button
              type="submit"
              disabled={loading || !urlInput.trim()}
              className="flex items-center justify-center gap-2 rounded-lg bg-st-navy px-6 py-3 text-sm font-semibold text-white shadow-md shadow-st-navy/20 transition hover:bg-st-blue-dark disabled:cursor-not-allowed disabled:opacity-50"
            >
              {loading ? (
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent"></span>
              ) : (
                <Search className="h-4 w-4" aria-hidden="true" />
              )}
              {loading ? 'Extracting Features...' : 'Analyze URL'}
            </button>
          </form>
        </Card>

        {/* Error Alert */}
        {error && (
          <div role="alert" className="flex items-center gap-3 rounded-lg bg-st-error-bg p-4 text-sm text-st-error-ink">
            <ShieldAlert className="h-5 w-5 shrink-0" aria-hidden="true" />
            <span>{error}</span>
          </div>
        )}

        {/* Before the first analysis */}
        {!result && !loading && !error && (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {LAYERS.map(({ icon: Icon, title, text }, idx) => (
              <div key={title} className="rounded-xl bg-white p-5 shadow-sm ring-1 ring-st-container/60">
                <div className="flex items-center justify-between">
                  <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-st-fixed text-st-blue-dark">
                    <Icon className="h-5 w-5" aria-hidden="true" />
                  </span>
                  <span className="text-[0.6875rem] font-bold uppercase tracking-wider text-st-outline">Layer {idx + 1}</span>
                </div>
                <h3 className="mt-3 font-manrope text-base font-semibold text-st-navy">{title}</h3>
                <p className="mt-1 text-sm text-st-muted">{text}</p>
              </div>
            ))}
          </div>
        )}

        {/* Results View */}
        {result && result.features && (
          <div className="space-y-6">

            {/* Overview Card */}
            <Card className="space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-4 border-b border-st-container pb-4">
                <div className="min-w-0">
                  <p className="text-[0.6875rem] font-bold uppercase tracking-wider text-st-outline">Analysis Report</p>
                  <h2 className="break-all font-manrope text-xl font-bold text-st-navy">{result.features.hostname || result.url}</h2>
                  <p className="mt-1 break-all text-xs text-st-muted">Raw input: <code className="font-mono text-st-ink">{result.url}</code></p>
                </div>
                <div>{getRiskBadge(result.risk_level, result.score)}</div>
              </div>

              <p className="text-sm leading-relaxed text-st-ink">{result.explanation}</p>

              {/* Risk Indicators */}
              {result.risk_indicators && result.risk_indicators.length > 0 && (
                <div className="space-y-2 rounded-lg bg-amber-50 p-4 ring-1 ring-amber-200">
                  <h3 className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-amber-800">
                    <AlertTriangle className="h-4 w-4" aria-hidden="true" /> Detected Risk Indicators ({result.risk_indicators.length})
                  </h3>
                  <BulletList items={result.risk_indicators} dotClass="bg-amber-500" textClass="text-amber-900" />
                </div>
              )}
            </Card>

            {/* Explainable Risk Scoring Engine & Factor Attribution Card */}
            {risk && (
              <Card className="space-y-6">
                <SectionHeader
                  icon={Scale}
                  iconClass="text-amber-600"
                  title="Explainable Risk Intelligence & Attribution"
                  text="Combines lexical features, domain intelligence, infrastructure and machine learning, with weights renormalized over the channels that were available."
                >
                  <Chip>Engine: {risk.engine_version}</Chip>
                  <Chip className="bg-st-fixed text-st-navy">ML Model: {risk.model_version || 'None'}</Chip>
                  <Chip>{new Date(risk.analysis_timestamp).toLocaleTimeString()} UTC</Chip>
                </SectionHeader>

                {/* Score vs Model Probability Comparison Banner */}
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                  <div className="flex items-center justify-between rounded-lg bg-st-low p-4">
                    <div>
                      <div className="text-sm font-semibold text-st-navy">Consolidated Risk Score (R)</div>
                      <div className="mt-0.5 text-xs text-st-muted">Multi-channel synthesized score</div>
                    </div>
                    <div className="text-right">
                      <div className={`font-mono text-2xl font-bold ${SCORE_STYLES[scoreTone(risk.risk_score)].text}`}>
                        {risk.risk_score} / 100
                      </div>
                      <span className="text-[0.625rem] font-bold uppercase tracking-wider text-st-muted">{risk.classification}</span>
                    </div>
                  </div>

                  <div className="flex items-center justify-between rounded-lg bg-st-low p-4">
                    <div>
                      <div className="text-sm font-semibold text-st-navy">Supervised Model Probability (P)</div>
                      <div className="mt-0.5 text-xs text-st-muted">Independent ML feature inference</div>
                    </div>
                    <div className="text-right">
                      <div className="font-mono text-2xl font-bold text-st-navy-2">
                        {ml && ml.is_model_loaded
                          ? `${(ml.malicious_probability * 100).toFixed(1)}%`
                          : 'N/A (Offline)'}
                      </div>
                      <span className="text-[0.625rem] font-bold uppercase tracking-wider text-st-muted">
                        {ml && ml.is_model_loaded ? ml.predicted_label : 'Unloaded'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Dynamic Channel Weights & Normalized Sub-scores */}
                <div className="space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h4 className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-st-blue-dark">
                      <Sliders className="h-4 w-4" aria-hidden="true" /> Active Channels & Weights
                    </h4>
                    <span className="text-[0.6875rem] italic text-st-outline">Weights renormalized over available services</span>
                  </div>

                  <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 xl:grid-cols-8">
                    {[
                      { key: 'lexical_structural', label: 'Lexical / Structural' },
                      { key: 'entropy_obfuscation', label: 'Entropy & Evasion' },
                      { key: 'homoglyph_lookalike', label: 'Homoglyph / Lookalike' },
                      { key: 'domain_registration', label: 'Registration & Age' },
                      { key: 'dns_reputation', label: 'DNS & Threat Feeds' },
                      { key: 'dga', label: 'DGA Algorithmic' },
                      { key: 'shortener_redirect', label: 'Redirects & SSRF' },
                      { key: 'machine_learning', label: 'Machine Learning' },
                    ].map(ch => {
                      const weight = risk.active_weights[ch.key] || 0;
                      const score = risk.channel_scores[ch.key] || 0;
                      const isActive = weight > 0;

                      return (
                        <div key={ch.key} className={`space-y-1.5 rounded-lg p-3 text-xs ring-1 ring-st-container ${isActive ? 'bg-st-low' : 'bg-st-low/40 opacity-60'}`}>
                          <div className="text-[0.6875rem] font-semibold text-st-navy">{ch.label}</div>
                          <div className="flex justify-between text-[0.6875rem]">
                            <span className="text-st-muted">Weight</span>
                            <span className="font-mono font-bold text-st-blue-dark">{isActive ? `${(weight * 100).toFixed(1)}%` : 'Excluded'}</span>
                          </div>
                          <div className="flex justify-between text-[0.6875rem]">
                            <span className="text-st-muted">Sub-score</span>
                            <span className={`font-mono font-semibold ${score >= 60 ? 'text-st-error' : score >= 30 ? 'text-amber-600' : 'text-st-ink'}`}>
                              {score.toFixed(1)}
                            </span>
                          </div>
                          <div className="h-1.5 w-full overflow-hidden rounded-full bg-st-container">
                            <div
                              className={`h-full transition-all duration-500 ${score >= 60 ? 'bg-st-error' : score >= 30 ? 'bg-amber-500' : 'bg-st-blue'}`}
                              style={{ width: `${Math.min(score, 100)}%` }}
                            />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Top Contributing Risk Factors (Factor Attribution) */}
                {risk.contributing_factors && risk.contributing_factors.length > 0 && (
                  <div className="space-y-3">
                    <h4 className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-st-navy-2">
                      <FileText className="h-4 w-4" aria-hidden="true" /> Top Contributing Risk Factors
                    </h4>

                    <div className="space-y-2">
                      {risk.contributing_factors.map((factor, idx) => {
                        const isMitigating = factor.impact_score < 0;
                        return (
                          <div key={idx} className="flex flex-col justify-between gap-2 rounded-lg bg-st-low p-3 text-xs sm:flex-row sm:items-center">
                            <div className="flex-1 space-y-1">
                              <div className="flex flex-wrap items-center gap-2">
                                <span className={`font-semibold ${isMitigating ? 'text-emerald-700' : 'text-st-navy'}`}>
                                  {factor.title}
                                </span>
                                <span className={`rounded px-2 py-0.5 font-mono text-[0.625rem] uppercase tracking-wider ${factor.epistemic_type === 'fact' ? 'bg-st-fixed text-st-navy' : factor.epistemic_type === 'heuristic' ? 'bg-amber-100 text-amber-800' : 'bg-violet-100 text-violet-800'}`}>
                                  {factor.epistemic_type}
                                </span>
                                <span className="font-mono text-[0.625rem] text-st-outline">
                                  [{factor.category}]
                                </span>
                              </div>
                              <p className="text-[0.6875rem] leading-relaxed text-st-muted">
                                {factor.evidence}
                              </p>
                            </div>

                            <div className="flex shrink-0 items-center justify-between sm:flex-col sm:items-end sm:justify-center">
                              <span className={`font-mono text-sm font-bold ${isMitigating ? 'text-emerald-700' : 'text-st-error'}`}>
                                {factor.impact_score > 0 ? `+${factor.impact_score.toFixed(1)}` : factor.impact_score.toFixed(1)} pts
                              </span>
                              <span className="text-[0.625rem] uppercase text-st-outline">
                                Confidence: {factor.confidence}
                              </span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Evidence hierarchy: facts vs heuristics vs predictions */}
                {risk.epistemic_breakdown && (
                  <div className="space-y-3">
                    <h4 className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-st-navy">
                      <BrainCircuit className="h-4 w-4 text-st-blue" aria-hidden="true" /> Evidence Hierarchy
                    </h4>

                    <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                      <SubCard
                        title="Observed Facts"
                        icon={CheckCircle2}
                        titleClass="text-st-blue-dark"
                        badge={<span className="font-mono text-[0.6875rem] text-st-outline">{risk.epistemic_breakdown.observed_facts.length}</span>}
                      >
                        <BulletList items={risk.epistemic_breakdown.observed_facts} dotClass="bg-st-blue" />
                      </SubCard>

                      <SubCard
                        title="Heuristic Indicators"
                        icon={AlertTriangle}
                        titleClass="text-amber-700"
                        badge={<span className="font-mono text-[0.6875rem] text-st-outline">{risk.epistemic_breakdown.heuristic_indicators.length}</span>}
                      >
                        {risk.epistemic_breakdown.heuristic_indicators.length > 0 ? (
                          <BulletList items={risk.epistemic_breakdown.heuristic_indicators} dotClass="bg-amber-500" />
                        ) : (
                          <p className="p-2 text-center text-[0.6875rem] italic text-st-outline">No heuristic anomaly thresholds breached.</p>
                        )}
                      </SubCard>

                      <SubCard
                        title="Model Predictions"
                        icon={Cpu}
                        titleClass="text-violet-700"
                        badge={<span className="font-mono text-[0.6875rem] text-st-outline">{risk.epistemic_breakdown.model_predictions.length}</span>}
                      >
                        <BulletList items={risk.epistemic_breakdown.model_predictions} dotClass="bg-violet-500" />
                      </SubCard>
                    </div>
                  </div>
                )}

                {/* Analysis Limitations Banner */}
                {risk.analysis_limitations && risk.analysis_limitations.length > 0 && (
                  <div className="space-y-2 rounded-lg bg-st-fixed/50 p-4">
                    <h4 className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-st-navy-2">
                      <Info className="h-4 w-4" aria-hidden="true" /> Service Limitations & Fallbacks ({risk.analysis_limitations.length})
                    </h4>
                    <BulletList items={risk.analysis_limitations} dotClass="bg-st-navy-2" />
                  </div>
                )}
              </Card>
            )}

            {/* Feature Extraction Grid */}
            <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
              <Card className="space-y-2">
                <h3 className="mb-2 flex items-center gap-2 text-sm font-bold text-st-navy">
                  <Globe className="h-4 w-4 text-st-blue-dark" aria-hidden="true" /> Structure & Lengths
                </h3>
                <Row label="URL Length" value={result.features.url_length} tone="accent" />
                <Row label="Hostname Length" value={result.features.hostname_length} tone="accent" />
                <Row label="Registered Domain" value={result.features.registered_domain || 'N/A'} tone="accent" truncate />
                <Row label="Subdomain" value={result.features.subdomain || 'None'} tone="accent" truncate />
                <Row label="TLD" value={`.${result.features.tld}`} tone="accent" />
                <Row label="Path Depth" value={result.features.path_depth} tone="accent" />
              </Card>

              <Card className="space-y-2">
                <h3 className="mb-2 flex items-center gap-2 text-sm font-bold text-st-navy">
                  <Code className="h-4 w-4 text-st-blue-dark" aria-hidden="true" /> Entropy & Math Metrics
                </h3>
                <Row label="URL Entropy" value={`${result.features.url_entropy} bits/char`} tone="accent" />
                <Row label="Hostname Entropy" value={`${result.features.hostname_entropy} bits/char`} tone="accent" />
                <Row label="Digit Ratio" value={`${(result.features.digit_ratio * 100).toFixed(1)}%`} tone="accent" />
                <Row label="Max Consecutive Digits" value={result.features.max_consecutive_digits} tone="accent" />
                <Row label="Max Char Repetition" value={result.features.max_character_repetition} tone="accent" />
                <Row label="Special Chars Count" value={result.features.num_special_chars} tone="accent" />
              </Card>

              <Card className="space-y-2">
                <h3 className="mb-2 flex items-center gap-2 text-sm font-bold text-st-navy">
                  <Key className="h-4 w-4 text-st-blue-dark" aria-hidden="true" /> Security & Obfuscation Flags
                </h3>
                <Row label="Is IP Address Host" value={result.features.is_ip_address ? `YES (${result.features.ip_type})` : 'NO'} tone={result.features.is_ip_address ? 'warn' : 'muted'} />
                <Row label="Homoglyph / Lookalike" value={result.features.has_homoglyphs ? 'DETECTED' : 'Clean'} tone={result.features.has_homoglyphs ? 'danger' : 'muted'} />
                <Row label="Punycode (xn--)" value={result.features.is_punycode ? 'YES' : 'NO'} tone={result.features.is_punycode ? 'warn' : 'muted'} />
                <Row label="Double Percent Encoded" value={result.features.is_double_encoded ? 'YES' : 'NO'} tone={result.features.is_double_encoded ? 'warn' : 'muted'} />
                <Row label="Contains '@' Delimiter" value={result.features.has_at_symbol ? 'YES' : 'NO'} tone={result.features.has_at_symbol ? 'warn' : 'muted'} />
                <Row label="Suspicious Keywords" value={`${result.features.suspicious_keyword_count} matched`} tone="accent" />
              </Card>
            </div>

            {/* Domain Intelligence Section (Layer 2) */}
            {domain && (
              <Card className="space-y-6">
                <SectionHeader icon={Globe} iconClass="text-emerald-600" title="Domain Intelligence & Infrastructure" text="RDAP registration, DNS records and reputation.">
                  <Chip>Sub-score: {domain.domain_risk_score}/100</Chip>
                </SectionHeader>

                <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
                  <SubCard title="Registration & Age" titleClass="text-emerald-700">
                    <div>
                      <Row label="Registrar" value={domain.registration.registrar || 'Protected / Unknown'} truncate />
                      <Row
                        label="Domain Age"
                        value={domain.registration.age_days !== null
                          ? `${domain.registration.age_days} days ${domain.registration.is_nrd ? '(NRD <= 30d)' : ''}`
                          : 'Unavailable'}
                        tone={domain.registration.is_nrd ? 'danger' : 'ok'}
                      />
                      <Row label="Created Date" value={domain.registration.creation_date ? domain.registration.creation_date.split('T')[0] : 'N/A'} tone="muted" />
                      <Row label="DNSSEC Status" value={domain.registration.dnssec_enabled ? 'Signed' : 'Unsigned'} tone={domain.registration.dnssec_enabled ? 'ok' : 'muted'} />
                      <Row label="Data Source" value={String(domain.registration.data_source).toUpperCase()} tone="muted" />
                    </div>
                  </SubCard>

                  <SubCard title="DNS Infrastructure" titleClass="text-st-blue-dark">
                    <div>
                      <Row label="DNS Resolution" value={domain.dns.dns_resolved ? 'Resolved' : 'NXDOMAIN / Unresolved'} tone={domain.dns.dns_resolved ? 'ok' : 'warn'} />
                      <Row label="Resolved IPs (A)" value={`${domain.dns.ip_count} IP(s)`} tone="accent" />
                      <Row label="MX (Mail Exchange)" value={domain.dns.has_mx_records ? 'Configured' : 'None'} tone={domain.dns.has_mx_records ? 'ok' : 'muted'} />
                      <Row label="Fast-Flux Pattern" value={domain.dns.is_fast_flux ? 'DETECTED' : 'Normal'} tone={domain.dns.is_fast_flux ? 'danger' : 'muted'} />
                      <Row label="Dynamic DNS Host" value={domain.dns.is_dynamic_dns ? 'Yes (DDNS)' : 'No'} tone={domain.dns.is_dynamic_dns ? 'warn' : 'muted'} />
                    </div>
                  </SubCard>

                  <SubCard title="Reputation & Indicators" titleClass="text-violet-700">
                    <div>
                      <Row label="Known Threat" value={domain.reputation.is_known_threat ? 'MATCH FOUND' : 'Clean'} tone={domain.reputation.is_known_threat ? 'danger' : 'ok'} />
                      <Row label="Threat Source" value={domain.reputation.reputation_source || 'Local Heuristics'} tone="muted" />
                    </div>
                    {domain.dns.a_records.length > 0 && (
                      <div className="pt-1">
                        <span className="mb-1 block text-xs text-st-muted">Resolved IP list:</span>
                        <div className="rounded bg-white p-2 font-mono text-[0.6875rem] text-st-blue-dark ring-1 ring-st-container">
                          {domain.dns.a_records.slice(0, 3).join(', ')}
                          {domain.dns.a_records.length > 3 ? '...' : ''}
                        </div>
                      </div>
                    )}
                  </SubCard>
                </div>
              </Card>
            )}

            {/* Threat Infrastructure Section (Layer 3: DGA & Safe Redirect Chains) */}
            {infra && (
              <Card className="space-y-6">
                <SectionHeader icon={GitFork} iconClass="text-violet-600" title="Threat Infrastructure Analysis" text="DGA detection, URL shorteners and safe redirect-chain tracing.">
                  <Chip>Sub-score: {infra.infrastructure_risk_score}/100</Chip>
                  <span className="inline-flex items-center gap-1 rounded-full bg-emerald-100 px-2.5 py-1 text-[0.6875rem] font-semibold text-emerald-800">
                    <Shield className="h-3.5 w-3.5" aria-hidden="true" /> SSRF & Rebinding Protected
                  </span>
                </SectionHeader>

                <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
                  <SubCard
                    title="DGA Analysis"
                    icon={Cpu}
                    titleClass="text-violet-700"
                    badge={
                      <span className={`rounded px-2 py-0.5 font-mono text-[0.6875rem] font-semibold ${infra.dga.is_dga_suspected ? 'bg-st-error-bg text-st-error-ink' : 'bg-emerald-100 text-emerald-800'}`}>
                        {infra.dga.is_dga_suspected ? 'DGA SUSPECTED' : 'NATURAL / BENIGN'}
                      </span>
                    }
                  >
                    <div>
                      <Row label="Analyzed Label" value={infra.dga.label} tone="accent" truncate />
                      <Row label="Label Entropy" value={`${infra.dga.label_entropy.toFixed(3)} bits/char`} tone={infra.dga.label_entropy >= 3.6 ? 'warn' : 'default'} />
                      <Row label="Vowel / Consonant" value={`${(infra.dga.vowel_ratio * 100).toFixed(0)}% / ${(infra.dga.consonant_ratio * 100).toFixed(0)}%`} />
                      <Row label="Max Consonant Run" value={infra.dga.max_consecutive_consonants} />
                      <Row label="Bigram Perplexity" value={infra.dga.bigram_perplexity.toFixed(2)} />
                      <Row label="Algorithmic Likelihood" value={`${(infra.dga.dga_score * 100).toFixed(0)}%`} tone="accent" />
                      {infra.dga.dga_family_hint && <Row label="Pattern Hint" value={infra.dga.dga_family_hint} tone="warn" />}
                    </div>
                  </SubCard>

                  <SubCard
                    title="Shortener & Resolution"
                    icon={Link2}
                    titleClass="text-st-blue-dark"
                    badge={
                      <span className={`rounded px-2 py-0.5 font-mono text-[0.6875rem] font-semibold ${infra.redirect_chain.is_shortened ? 'bg-amber-100 text-amber-800' : 'bg-st-container text-st-muted'}`}>
                        {infra.redirect_chain.is_shortened ? (infra.redirect_chain.shortener_provider || 'Shortened') : 'Direct URL'}
                      </span>
                    }
                  >
                    <div>
                      <Row label="Redirect Hops" value={infra.redirect_chain.total_hops} tone="accent" />
                      <Row label="Cross-Domain Pivot" value={infra.redirect_chain.destination_domain_changed ? 'YES (Changed)' : 'NO'} tone={infra.redirect_chain.destination_domain_changed ? 'warn' : 'muted'} />
                      <Row label="Redirect Loop" value={infra.redirect_chain.has_redirect_loop ? 'DETECTED' : 'None'} tone={infra.redirect_chain.has_redirect_loop ? 'danger' : 'muted'} />
                      <Row label="SSRF Boundary Check" value={infra.redirect_chain.ssrf_blocked ? 'BLOCKED' : 'Clean IP'} tone={infra.redirect_chain.ssrf_blocked ? 'danger' : 'ok'} />
                    </div>
                    <div className="pt-1">
                      <span className="mb-1 block text-xs text-st-muted">Final resolved destination:</span>
                      <div className="select-all break-all rounded bg-white p-2 font-mono text-[0.6875rem] text-st-blue-dark ring-1 ring-st-container">
                        {infra.redirect_chain.final_url || result.url}
                      </div>
                    </div>
                  </SubCard>

                  <SubCard title="Observed Hop Trace" icon={ExternalLink} titleClass="text-st-navy-2" className="md:col-span-2 lg:col-span-1">
                    {infra.redirect_chain.chain_hops && infra.redirect_chain.chain_hops.length > 0 ? (
                      <div className="max-h-56 space-y-2 overflow-y-auto pr-1">
                        {infra.redirect_chain.chain_hops.map((hop, index) => (
                          <div key={index} className="space-y-1 rounded bg-white p-2.5 text-xs ring-1 ring-st-container">
                            <div className="flex items-center justify-between text-[0.6875rem]">
                              <span className="font-mono font-bold text-st-blue-dark">Hop #{hop.hop_number}</span>
                              <span className={`rounded px-1.5 py-0.5 font-mono text-[0.625rem] ${
                                hop.status_code >= 300 && hop.status_code < 400
                                  ? 'bg-amber-100 text-amber-800'
                                  : hop.status_code >= 200 && hop.status_code < 300
                                  ? 'bg-emerald-100 text-emerald-800'
                                  : 'bg-st-container text-st-muted'
                              }`}>
                                HTTP {hop.status_code}
                              </span>
                            </div>
                            <div className="truncate font-mono text-[0.6875rem] text-st-ink" title={hop.url}>{hop.domain}</div>
                            {hop.resolved_ip && (
                              <div className="font-mono text-[0.625rem] text-st-outline">Verified IP: {hop.resolved_ip}</div>
                            )}
                            {hop.is_cross_domain && (
                              <div className="flex items-center gap-1 text-[0.625rem] font-semibold text-amber-700">
                                <CornerDownRight className="h-3 w-3" aria-hidden="true" /> Cross-domain redirect
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="p-3 text-center text-xs italic text-st-outline">No redirection hops observed. Destination requested directly.</p>
                    )}
                  </SubCard>
                </div>

                {/* Threat Infrastructure Risk Indicators */}
                {infra.infrastructure_indicators && infra.infrastructure_indicators.length > 0 && (
                  <div className="space-y-2 rounded-lg bg-violet-50 p-4 ring-1 ring-violet-200">
                    <h4 className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-violet-800">
                      <AlertTriangle className="h-4 w-4" aria-hidden="true" /> Threat Infrastructure Observations ({infra.infrastructure_indicators.length})
                    </h4>
                    <BulletList items={infra.infrastructure_indicators} dotClass="bg-violet-500" textClass="text-violet-900" />
                  </div>
                )}
              </Card>
            )}

            {/* Machine Learning Layer (Layer 4: Supervised Classifier Inference) */}
            {ml && ml.is_model_loaded && (
              <Card className="space-y-6">
                <SectionHeader icon={BrainCircuit} iconClass="text-st-navy-2" title={`Layer 4: Machine Learning Classification (${ml.model_name})`}>
                  <Chip>Latency: {ml.inference_time_ms} ms</Chip>
                  <span className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 font-mono text-[0.6875rem] font-bold ${
                    ml.predicted_label === 'malicious' ? 'bg-st-error-bg text-st-error-ink' : 'bg-emerald-100 text-emerald-800'
                  }`}>
                    {ml.predicted_label === 'malicious' ? 'CLASSIFIED MALICIOUS' : 'CLASSIFIED LEGITIMATE'}
                  </span>
                </SectionHeader>

                <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
                  <SubCard title="Prediction Probabilities" titleClass="text-st-navy-2">
                    <div>
                      <div className="mb-1 flex justify-between text-xs">
                        <span className="text-st-muted">Malicious Probability</span>
                        <span className="font-mono font-bold text-st-navy-2">{(ml.malicious_probability * 100).toFixed(1)}%</span>
                      </div>
                      <div className="h-2 w-full overflow-hidden rounded-full bg-st-container">
                        <div
                          className={`h-full transition-all duration-500 ${ml.malicious_probability >= ml.decision_threshold ? 'bg-st-error' : 'bg-emerald-500'}`}
                          style={{ width: `${Math.min(ml.malicious_probability * 100, 100)}%` }}
                        />
                      </div>
                    </div>
                    <div className="pt-1">
                      <Row label="Decision Threshold" value={ml.decision_threshold.toFixed(2)} tone="muted" />
                      <Row label="Confidence Score" value={`${ml.confidence.toFixed(1)}%`} tone="accent" />
                      <Row label="Feature Dimensions" value={`${ml.feature_count} features`} tone="muted" />
                    </div>
                  </SubCard>

                  <SubCard title="Model Operational Specs" titleClass="text-st-blue-dark">
                    <div>
                      <Row label="Active Classifier" value={ml.model_name} tone="accent" />
                      <Row label="Pre-trained Model Status" value="Loaded in RAM" tone="ok" />
                      <Row label="Inference Latency" value={`${ml.inference_time_ms} ms`} tone="accent" />
                      <Row label="Evaluation Strategy" value="Domain-Grouped (Leak-free)" tone="muted" />
                      <Row label="Re-training Trigger" value="Scheduled batch" tone="muted" />
                    </div>
                  </SubCard>

                  <SubCard title="Top Contributing Feature Signals" titleClass="text-violet-700">
                    {ml.top_risk_features && ml.top_risk_features.length > 0 ? (
                      <BulletList items={ml.top_risk_features} dotClass="bg-violet-500" />
                    ) : (
                      <p className="p-3 text-center text-xs italic text-st-outline">No elevated risk signals observed across extracted features.</p>
                    )}
                  </SubCard>
                </div>
              </Card>
            )}

            {/* Raw JSON Features View */}
            <Card>
              <details>
                <summary className="flex cursor-pointer items-center gap-2 text-sm font-bold text-st-navy">
                  <Terminal className="h-4 w-4 text-st-blue-dark" aria-hidden="true" /> Extracted Multi-Layer JSON Payload
                </summary>
                <pre className="mt-3 max-h-72 overflow-x-auto rounded-lg bg-st-ink p-4 font-mono text-xs text-st-fixed">
                  {JSON.stringify(result, null, 2)}
                </pre>
              </details>
            </Card>

          </div>
        )}

      </div>
    </AppShell>
  );
}
