import React, { useState } from 'react';
import axios from 'axios';
import { Search, ShieldAlert, ShieldCheck, AlertTriangle, Layers, Globe, Code, Key, Terminal } from 'lucide-react';

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

            {/* Raw JSON Features View */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6">
              <h3 className="text-sm font-semibold text-slate-300 flex items-center gap-2 mb-3">
                <Terminal className="w-4 h-4 text-cyan-400" /> Extracted ML Feature Payload (JSON)
              </h3>
              <pre className="bg-slate-950 p-4 rounded-lg overflow-x-auto text-xs text-cyan-300 font-mono border border-slate-800 max-h-72">
                {JSON.stringify(result.features, null, 2)}
              </pre>
            </div>

          </div>
        )}

      </div>
    </div>
  );
}
