import React, { useState } from 'react';
import axios from 'axios';
import { Search, ShieldAlert, ShieldCheck, AlertTriangle, Layers, Globe, Code, Key, Terminal, GitFork, Cpu, Shield, CornerDownRight, ExternalLink, Link2 } from 'lucide-react';

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
      } catch (directErr) {
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
    if (score >= 75) {
      return (
        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-red-500/20 text-red-400 border border-red-500/30">
          <ShieldAlert className="w-4 h-4" /> {level} ({score}/100)
        </span>
      );
    } else if (score >= 50) {
      return (
        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-orange-500/20 text-orange-400 border border-orange-500/30">
          <AlertTriangle className="w-4 h-4" /> {level} ({score}/100)
        </span>
      );
    } else if (score >= 25) {
      return (
        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">
          <AlertTriangle className="w-4 h-4" /> {level} ({score}/100)
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
        <ShieldCheck className="w-4 h-4" /> {level} ({score}/100)
      </span>
    );
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 md:p-10 font-sans">
      <div className="max-w-6xl mx-auto space-y-8">
        
        {/* Header */}
        <header className="border-b border-slate-800 pb-6">
          <div className="flex items-center gap-3 mb-2">
            <Layers className="w-8 h-8 text-cyan-400" />
            <h1 className="text-3xl font-bold tracking-tight bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
              Intelligent URL & Domain Analyzer
            </h1>
          </div>
          <p className="text-slate-400 text-sm">
            Component C1 — Multi-Layer URL & Domain Intelligence Framework (Layer 1 Lexical Feature Extraction Engine)
          </p>
        </header>

        {/* Input Form */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 shadow-xl backdrop-blur-sm">
          <form onSubmit={handleAnalyze} className="flex flex-col md:flex-row gap-4">
            <div className="relative flex-1">
              <Globe className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500 w-5 h-5" />
              <input
                type="text"
                placeholder="Enter URL or domain (e.g. http://login.paypal.verify-account.com/auth)"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 focus:border-cyan-500 text-slate-100 placeholder-slate-500 text-sm rounded-lg pl-12 pr-4 py-3 outline-none transition"
              />
            </div>
            <button
              type="submit"
              disabled={loading || !urlInput.trim()}
              className="bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 text-white font-medium text-sm px-6 py-3 rounded-lg flex items-center justify-center gap-2 transition cursor-pointer shadow-lg shadow-cyan-500/20"
            >
              {loading ? (
                <span className="animate-spin border-2 border-white border-t-transparent rounded-full w-4 h-4"></span>
              ) : (
                <Search className="w-4 h-4" />
              )}
              {loading ? 'Extracting Features...' : 'Analyze URL'}
            </button>
          </form>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="bg-red-950/50 border border-red-800/80 rounded-lg p-4 text-red-300 text-sm flex items-center gap-3">
            <ShieldAlert className="w-5 h-5 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Results View */}
        {result && result.features && (
          <div className="space-y-6 animate-fade-in">
            
            {/* Overview Card */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
                <div>
                  <h2 className="text-xl font-semibold text-slate-100 flex items-center gap-2">
                    Analysis Report for: <span className="font-mono text-cyan-300 text-base">{result.features.hostname || result.url}</span>
                  </h2>
                  <p className="text-xs text-slate-400 mt-1">Raw Input: <code className="text-slate-300">{result.url}</code></p>
                </div>
                <div>{getRiskBadge(result.risk_level, result.score)}</div>
              </div>

              <p className="text-sm text-slate-300 leading-relaxed">{result.explanation}</p>

              {/* Risk Indicators */}
              {result.risk_indicators && result.risk_indicators.length > 0 && (
                <div className="bg-slate-950/60 border border-amber-900/30 rounded-lg p-4 space-y-2">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-amber-400 flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4" /> Detected Risk Indicators ({result.risk_indicators.length})
                  </h3>
                  <ul className="list-disc list-inside text-xs text-slate-300 space-y-1">
                    {result.risk_indicators.map((ind, idx) => (
                      <li key={idx} className="text-amber-200/90">{ind}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            {/* Feature Extraction Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              
              {/* Structural & Length Features */}
              <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-3">
                <h3 className="text-sm font-semibold text-cyan-400 flex items-center gap-2">
                  <Globe className="w-4 h-4" /> Structure & Lengths
                </h3>
                <div className="text-xs space-y-2 text-slate-300">
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span>URL Length</span> <span className="font-mono text-cyan-300">{result.features.url_length}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span>Hostname Length</span> <span className="font-mono text-cyan-300">{result.features.hostname_length}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span>Registered Domain</span> <span className="font-mono text-cyan-300">{result.features.registered_domain || 'N/A'}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span>Subdomain</span> <span className="font-mono text-cyan-300">{result.features.subdomain || 'None'}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span>TLD</span> <span className="font-mono text-cyan-300">.{result.features.tld}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span>Path Depth</span> <span className="font-mono text-cyan-300">{result.features.path_depth}</span>
                  </div>
                </div>
              </div>

              {/* Entropy & Mathematical Metrics */}
              <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-3">
                <h3 className="text-sm font-semibold text-blue-400 flex items-center gap-2">
                  <Code className="w-4 h-4" /> Entropy & Math Metrics
                </h3>
                <div className="text-xs space-y-2 text-slate-300">
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span>URL Entropy</span> <span className="font-mono text-blue-300">{result.features.url_entropy} bits/char</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span>Hostname Entropy</span> <span className="font-mono text-blue-300">{result.features.hostname_entropy} bits/char</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span>Digit Ratio</span> <span className="font-mono text-blue-300">{(result.features.digit_ratio * 100).toFixed(1)}%</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span>Max Consecutive Digits</span> <span className="font-mono text-blue-300">{result.features.max_consecutive_digits}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span>Max Char Repetition</span> <span className="font-mono text-blue-300">{result.features.max_character_repetition}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span>Special Chars Count</span> <span className="font-mono text-blue-300">{result.features.num_special_chars}</span>
                  </div>
                </div>
              </div>

              {/* Security & Obfuscation Flags */}
              <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 space-y-3">
                <h3 className="text-sm font-semibold text-purple-400 flex items-center gap-2">
                  <Key className="w-4 h-4" /> Security & Obfuscation Flags
                </h3>
                <div className="text-xs space-y-2 text-slate-300">
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span>Is IP Address Host</span>
                    <span className={`font-mono ${result.features.is_ip_address ? 'text-amber-400' : 'text-slate-400'}`}>
                      {result.features.is_ip_address ? `YES (${result.features.ip_type})` : 'NO'}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span>Homoglyph / Lookalike</span>
                    <span className={`font-mono ${result.features.has_homoglyphs ? 'text-red-400 font-bold' : 'text-slate-400'}`}>
                      {result.features.has_homoglyphs ? 'DETECTED' : 'Clean'}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span>Punycode (xn--)</span>
                    <span className={`font-mono ${result.features.is_punycode ? 'text-amber-400' : 'text-slate-400'}`}>
                      {result.features.is_punycode ? 'YES' : 'NO'}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span>Double Percent Encoded</span>
                    <span className={`font-mono ${result.features.is_double_encoded ? 'text-amber-400' : 'text-slate-400'}`}>
                      {result.features.is_double_encoded ? 'YES' : 'NO'}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span>Contains '@' Delimiter</span>
                    <span className={`font-mono ${result.features.has_at_symbol ? 'text-amber-400' : 'text-slate-400'}`}>
                      {result.features.has_at_symbol ? 'YES' : 'NO'}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-slate-800/60">
                    <span>Suspicious Keywords</span>
                    <span className="font-mono text-purple-300">{result.features.suspicious_keyword_count} matched</span>
                  </div>
                </div>
              </div>

            </div>

            {/* Domain Intelligence Section (Layer 2) */}
            {result.domain_intelligence && (
              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 space-y-6">
                <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                  <div className="flex items-center gap-2">
                    <Globe className="w-5 h-5 text-emerald-400" />
                    <h3 className="text-base font-semibold text-slate-100">
                      Domain Intelligence & Infrastructure (RDAP, DNS & Reputation)
                    </h3>
                  </div>
                  <span className="text-xs px-2.5 py-1 rounded bg-slate-800 text-slate-300 font-mono">
                    Sub-score: {result.domain_intelligence.domain_risk_score}/100
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  {/* Registration & WHOIS/RDAP */}
                  <div className="bg-slate-950/70 border border-slate-800/80 rounded-lg p-4 space-y-3">
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                      Registration & Age
                    </h4>
                    <div className="text-xs space-y-2 text-slate-300">
                      <div className="flex justify-between py-1 border-b border-slate-800/50">
                        <span>Registrar</span>
                        <span className="font-mono text-slate-200 truncate max-w-[150px]">
                          {result.domain_intelligence.registration.registrar || 'Protected / Unknown'}
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-800/50">
                        <span>Domain Age</span>
                        <span className={`font-mono font-bold ${result.domain_intelligence.registration.is_nrd ? 'text-red-400' : 'text-emerald-300'}`}>
                          {result.domain_intelligence.registration.age_days !== null
                            ? `${result.domain_intelligence.registration.age_days} days ${result.domain_intelligence.registration.is_nrd ? '(NRD <= 30d)' : ''}`
                            : 'Unavailable'}
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-800/50">
                        <span>Created Date</span>
                        <span className="font-mono text-slate-400">
                          {result.domain_intelligence.registration.creation_date
                            ? result.domain_intelligence.registration.creation_date.split('T')[0]
                            : 'N/A'}
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-800/50">
                        <span>DNSSEC Status</span>
                        <span className={`font-mono ${result.domain_intelligence.registration.dnssec_enabled ? 'text-emerald-400' : 'text-slate-500'}`}>
                          {result.domain_intelligence.registration.dnssec_enabled ? 'Signed' : 'Unsigned'}
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-800/50">
                        <span>Data Source</span>
                        <span className="font-mono text-slate-400 uppercase">
                          {result.domain_intelligence.registration.data_source}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* DNS Infrastructure */}
                  <div className="bg-slate-950/70 border border-slate-800/80 rounded-lg p-4 space-y-3">
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-blue-400 flex items-center gap-1.5">
                      DNS Infrastructure
                    </h4>
                    <div className="text-xs space-y-2 text-slate-300">
                      <div className="flex justify-between py-1 border-b border-slate-800/50">
                        <span>DNS Resolution</span>
                        <span className={`font-mono ${result.domain_intelligence.dns.dns_resolved ? 'text-emerald-400' : 'text-amber-400'}`}>
                          {result.domain_intelligence.dns.dns_resolved ? 'Resolved' : 'NXDOMAIN / Unresolved'}
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-800/50">
                        <span>Resolved IPs (A)</span>
                        <span className="font-mono text-blue-300">
                          {result.domain_intelligence.dns.ip_count} IP(s)
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-800/50">
                        <span>MX (Mail Exchange)</span>
                        <span className={`font-mono ${result.domain_intelligence.dns.has_mx_records ? 'text-emerald-400' : 'text-slate-500'}`}>
                          {result.domain_intelligence.dns.has_mx_records ? 'Configured' : 'None'}
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-800/50">
                        <span>Fast-Flux Pattern</span>
                        <span className={`font-mono ${result.domain_intelligence.dns.is_fast_flux ? 'text-red-400 font-bold' : 'text-slate-400'}`}>
                          {result.domain_intelligence.dns.is_fast_flux ? 'DETECTED' : 'Normal'}
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-800/50">
                        <span>Dynamic DNS Host</span>
                        <span className={`font-mono ${result.domain_intelligence.dns.is_dynamic_dns ? 'text-amber-400' : 'text-slate-400'}`}>
                          {result.domain_intelligence.dns.is_dynamic_dns ? 'Yes (DDNS)' : 'No'}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Threat Reputation */}
                  <div className="bg-slate-950/70 border border-slate-800/80 rounded-lg p-4 space-y-3">
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-purple-400 flex items-center gap-1.5">
                      Reputation & Indicators
                    </h4>
                    <div className="text-xs space-y-2 text-slate-300">
                      <div className="flex justify-between py-1 border-b border-slate-800/50">
                        <span>Known Threat</span>
                        <span className={`font-mono ${result.domain_intelligence.reputation.is_known_threat ? 'text-red-400 font-bold' : 'text-emerald-400'}`}>
                          {result.domain_intelligence.reputation.is_known_threat ? 'MATCH FOUND' : 'Clean'}
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-800/50">
                        <span>Threat Source</span>
                        <span className="font-mono text-slate-400">
                          {result.domain_intelligence.reputation.reputation_source || 'Local Heuristics'}
                        </span>
                      </div>
                      {result.domain_intelligence.dns.a_records.length > 0 && (
                        <div className="pt-1">
                          <span className="text-slate-500 block mb-1">Resolved IP List:</span>
                          <div className="font-mono text-[11px] text-cyan-400/90 bg-slate-900 p-1.5 rounded border border-slate-800">
                            {result.domain_intelligence.dns.a_records.slice(0, 3).join(', ')}
                            {result.domain_intelligence.dns.a_records.length > 3 ? '...' : ''}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Threat Infrastructure Section (Layer 3: DGA & Safe Redirect Chains) */}
            {result.threat_infrastructure && (
              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 space-y-6">
                <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
                  <div className="flex items-center gap-2">
                    <GitFork className="w-5 h-5 text-purple-400" />
                    <h3 className="text-base font-semibold text-slate-100">
                      Threat Infrastructure Analysis (DGA, Shorteners & Safe Redirects)
                    </h3>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-xs px-2.5 py-1 rounded bg-slate-800 text-slate-300 font-mono">
                      Sub-score: {result.threat_infrastructure.infrastructure_risk_score}/100
                    </span>
                    <span className="inline-flex items-center gap-1 text-xs px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                      <Shield className="w-3.5 h-3.5" /> SSRF & Rebinding Protected
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                  {/* DGA Statistical Analysis */}
                  <div className="bg-slate-950/70 border border-slate-800/80 rounded-lg p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <h4 className="text-xs font-semibold uppercase tracking-wider text-purple-400 flex items-center gap-1.5">
                        <Cpu className="w-4 h-4" /> DGA Analysis
                      </h4>
                      <span className={`text-[11px] px-2 py-0.5 rounded font-mono font-semibold ${
                        result.threat_infrastructure.dga.is_dga_suspected
                          ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                          : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                      }`}>
                        {result.threat_infrastructure.dga.is_dga_suspected ? 'DGA SUSPECTED' : 'NATURAL / BENIGN'}
                      </span>
                    </div>

                    <div className="text-xs space-y-2 text-slate-300">
                      <div className="flex justify-between py-1 border-b border-slate-800/50">
                        <span>Analyzed Label</span>
                        <span className="font-mono text-purple-300 truncate max-w-[130px]">
                          {result.threat_infrastructure.dga.label}
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-800/50">
                        <span>Label Entropy</span>
                        <span className={`font-mono ${
                          result.threat_infrastructure.dga.label_entropy >= 3.6 ? 'text-amber-400 font-bold' : 'text-slate-300'
                        }`}>
                          {result.threat_infrastructure.dga.label_entropy.toFixed(3)} bits/char
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-800/50">
                        <span>Vowel / Consonant</span>
                        <span className="font-mono text-slate-300">
                          {(result.threat_infrastructure.dga.vowel_ratio * 100).toFixed(0)}% / {(result.threat_infrastructure.dga.consonant_ratio * 100).toFixed(0)}%
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-800/50">
                        <span>Max Consonant Run</span>
                        <span className="font-mono text-slate-300">
                          {result.threat_infrastructure.dga.max_consecutive_consonants}
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-800/50">
                        <span>Bigram Perplexity</span>
                        <span className="font-mono text-slate-300">
                          {result.threat_infrastructure.dga.bigram_perplexity.toFixed(2)}
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-800/50">
                        <span>Algorithmic Likelihood</span>
                        <span className="font-mono text-purple-400 font-semibold">
                          {(result.threat_infrastructure.dga.dga_score * 100).toFixed(0)}%
                        </span>
                      </div>
                      {result.threat_infrastructure.dga.dga_family_hint && (
                        <div className="flex justify-between py-1 border-b border-slate-800/50">
                          <span>Pattern Hint</span>
                          <span className="font-mono text-amber-300 text-[11px]">
                            {result.threat_infrastructure.dga.dga_family_hint}
                          </span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* URL Shortener & Resolution */}
                  <div className="bg-slate-950/70 border border-slate-800/80 rounded-lg p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <h4 className="text-xs font-semibold uppercase tracking-wider text-cyan-400 flex items-center gap-1.5">
                        <Link2 className="w-4 h-4" /> Shortener & Resolution
                      </h4>
                      <span className={`text-[11px] px-2 py-0.5 rounded font-mono font-semibold ${
                        result.threat_infrastructure.redirect_chain.is_shortened
                          ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                          : 'bg-slate-800 text-slate-400'
                      }`}>
                        {result.threat_infrastructure.redirect_chain.is_shortened
                          ? (result.threat_infrastructure.redirect_chain.shortener_provider || 'Shortened')
                          : 'Direct URL'}
                      </span>
                    </div>

                    <div className="text-xs space-y-2 text-slate-300">
                      <div className="flex justify-between py-1 border-b border-slate-800/50">
                        <span>Redirect Hops</span>
                        <span className="font-mono text-cyan-300">
                          {result.threat_infrastructure.redirect_chain.total_hops}
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-800/50">
                        <span>Cross-Domain Pivot</span>
                        <span className={`font-mono ${
                          result.threat_infrastructure.redirect_chain.destination_domain_changed ? 'text-amber-400 font-bold' : 'text-slate-400'
                        }`}>
                          {result.threat_infrastructure.redirect_chain.destination_domain_changed ? 'YES (Changed)' : 'NO'}
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-800/50">
                        <span>Redirect Loop</span>
                        <span className={`font-mono ${
                          result.threat_infrastructure.redirect_chain.has_redirect_loop ? 'text-red-400 font-bold' : 'text-slate-400'
                        }`}>
                          {result.threat_infrastructure.redirect_chain.has_redirect_loop ? 'DETECTED' : 'None'}
                        </span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-slate-800/50">
                        <span>SSRF Boundary Check</span>
                        <span className={`font-mono ${
                          result.threat_infrastructure.redirect_chain.ssrf_blocked ? 'text-red-400 font-bold' : 'text-emerald-400'
                        }`}>
                          {result.threat_infrastructure.redirect_chain.ssrf_blocked ? 'BLOCKED' : 'Clean IP'}
                        </span>
                      </div>
                      <div className="pt-1">
                        <span className="text-slate-500 block mb-1">Final Resolved Destination:</span>
                        <div className="font-mono text-[11px] text-cyan-300 bg-slate-900 p-2 rounded border border-slate-800 break-all select-all">
                          {result.threat_infrastructure.redirect_chain.final_url || result.url}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Redirect Hops Chain */}
                  <div className="bg-slate-950/70 border border-slate-800/80 rounded-lg p-4 space-y-3 md:col-span-2 lg:col-span-1">
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-blue-400 flex items-center gap-1.5">
                      <ExternalLink className="w-4 h-4" /> Observed Hop Trace
                    </h4>
                    {result.threat_infrastructure.redirect_chain.chain_hops && result.threat_infrastructure.redirect_chain.chain_hops.length > 0 ? (
                      <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                        {result.threat_infrastructure.redirect_chain.chain_hops.map((hop, index) => (
                          <div
                            key={index}
                            className="p-2.5 rounded bg-slate-900/90 border border-slate-800 text-xs space-y-1"
                          >
                            <div className="flex items-center justify-between text-[11px]">
                              <span className="font-mono text-cyan-400 font-bold">
                                Hop #{hop.hop_number}
                              </span>
                              <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                                hop.status_code >= 300 && hop.status_code < 400
                                  ? 'bg-amber-500/20 text-amber-300'
                                  : hop.status_code >= 200 && hop.status_code < 300
                                  ? 'bg-emerald-500/20 text-emerald-300'
                                  : 'bg-slate-800 text-slate-300'
                              }`}>
                                HTTP {hop.status_code}
                              </span>
                            </div>
                            <div className="font-mono text-[11px] text-slate-300 truncate" title={hop.url}>
                              {hop.domain}
                            </div>
                            {hop.resolved_ip && (
                              <div className="text-[10px] text-slate-500 font-mono">
                                Verified IP: {hop.resolved_ip}
                              </div>
                            )}
                            {hop.is_cross_domain && (
                              <div className="text-[10px] text-amber-400 font-semibold flex items-center gap-1">
                                <CornerDownRight className="w-3 h-3" /> Cross-domain redirect
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-xs text-slate-500 italic p-3 text-center">
                        No redirection hops observed. Destination requested directly.
                      </div>
                    )}
                  </div>
                </div>

                {/* Threat Infrastructure Risk Indicators */}
                {result.threat_infrastructure.infrastructure_indicators && result.threat_infrastructure.infrastructure_indicators.length > 0 && (
                  <div className="bg-slate-950/60 border border-purple-900/30 rounded-lg p-4 space-y-2">
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-purple-400 flex items-center gap-1.5">
                      <AlertTriangle className="w-4 h-4" /> Threat Infrastructure Observations ({result.threat_infrastructure.infrastructure_indicators.length})
                    </h4>
                    <ul className="list-disc list-inside text-xs text-slate-300 space-y-1">
                      {result.threat_infrastructure.infrastructure_indicators.map((ind, idx) => (
                        <li key={idx} className="text-purple-200/90">{ind}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}

            {/* Raw JSON Features View */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6">
              <h3 className="text-sm font-semibold text-slate-300 flex items-center gap-2 mb-3">
                <Terminal className="w-4 h-4 text-cyan-400" /> Extracted Multi-Layer JSON Payload
              </h3>
              <pre className="bg-slate-950 p-4 rounded-lg overflow-x-auto text-xs text-cyan-300 font-mono border border-slate-800 max-h-72">
                {JSON.stringify(result, null, 2)}
              </pre>
            </div>

          </div>
        )}

      </div>
    </div>
  );
}
