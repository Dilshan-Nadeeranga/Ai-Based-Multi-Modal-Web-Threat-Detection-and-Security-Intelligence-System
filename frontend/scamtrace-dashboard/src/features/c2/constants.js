import { Code2, Globe, Languages, Layers, LayoutTemplate } from 'lucide-react'

// Colour language of the console: cyan = info, amber = suspicious, red = malicious, green = legitimate.
// Text colours are the 300/400 shades on slate-950 (all >= 4.5:1 contrast).
export const VERDICT_STYLE = {
  Legitimate: { text: 'text-emerald-300', ring: 'ring-emerald-400/50', bg: 'bg-emerald-400/10', bar: 'bg-emerald-400', hex: '#34d399', label: 'Legitimate' },
  Suspicious: { text: 'text-amber-300', ring: 'ring-amber-400/50', bg: 'bg-amber-400/10', bar: 'bg-amber-400', hex: '#fbbf24', label: 'Suspicious' },
  Malicious: { text: 'text-red-300', ring: 'ring-red-400/60', bg: 'bg-red-500/10', bar: 'bg-red-400', hex: '#f87171', label: 'Malicious' },
  none: { text: 'text-slate-300', ring: 'ring-slate-500/50', bg: 'bg-slate-500/10', bar: 'bg-slate-400', hex: '#94a3b8', label: 'No verdict' },
}

export const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
export const SEVERITY_STYLE = {
  critical: 'bg-red-500/15 text-red-300 ring-red-400/50',
  high: 'bg-orange-500/15 text-orange-300 ring-orange-400/40',
  medium: 'bg-amber-400/10 text-amber-300 ring-amber-400/40',
  low: 'bg-cyan-400/10 text-cyan-300 ring-cyan-400/30',
  info: 'bg-slate-500/15 text-slate-300 ring-slate-500/40',
}

export const CLASS_LABELS = {
  benign: 'Benign',
  phishing: 'Phishing',
  fake_ecommerce: 'Fake e-commerce',
  crypto_scam: 'Crypto scam',
  malware_delivery: 'Malware delivery',
}
export const CLASSES = Object.keys(CLASS_LABELS)

export const SOURCE_LABELS = {
  user: 'User check',
  api: 'API',
  threatradar_push: 'ThreatRadar (push)',
  threatradar_pull: 'ThreatRadar (pull)',
}

export const LANGUAGE_LABELS = {
  en: 'English', si: 'Sinhala', ta: 'Tamil', si_latn: 'Singlish', ta_latn: 'Tanglish',
  mixed: 'Mixed', other: 'Other', unknown: 'Unknown',
}

export const MODALITY = {
  fetch: { label: 'Fetch', icon: Globe },
  dom: { label: 'DOM', icon: LayoutTemplate },
  content: { label: 'Content', icon: Languages },
  behavior: { label: 'Behavior', icon: Code2 },
  fusion: { label: 'Fusion', icon: Layers },
}

export const ARM_LABELS = {
  dom: 'DOM-only',
  behavior: 'Behavior-only',
  text_tfidf: 'Text TF-IDF',
  text_xlmr: 'Text XLM-R',
}

// The real stages of the 9B-1 orchestrator, in order, and which timings_ms keys belong to each.
export const PIPELINE_STAGES = [
  { id: 'fetch', label: 'Fetch', keys: ['fetch'], note: 'static GET, no JavaScript, SSRF-guarded' },
  { id: 'preprocess', label: 'Preprocess', keys: ['preprocess', 'quality'], note: 'HTML → ParsedPage + quality check' },
  { id: 'dom', label: 'DOM', keys: ['dom_features', 'dom_model'], note: '52 structural features + Random Forest' },
  { id: 'content', label: 'Content / Language', keys: ['content'], note: 'segments, en / si / ta language ID' },
  { id: 'text', label: 'Text model', keys: ['text_models'], note: 'XLM-R + TF-IDF on page_text' },
  { id: 'js', label: 'JS analysis', keys: ['js_analysis'], note: 'tree-sitter AST, never executed' },
  { id: 'behavior', label: 'Behavior', keys: ['behavior', 'behavior_model'], note: 'source → sink taint flows' },
  { id: 'fusion', label: 'Fusion', keys: ['fusion'], note: 'weighted late fusion + verdict tiers' },
]

export const pct = (value, digits = 1) =>
  value === null || value === undefined || Number.isNaN(value) ? '—' : `${(value * 100).toFixed(digits)} %`
export const num = (value, digits = 3) =>
  value === null || value === undefined || Number.isNaN(value) ? '—' : Number(value).toFixed(digits)

export function formatTime(iso) {
  if (!iso) return '—'
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? String(iso) : date.toLocaleString()
}
