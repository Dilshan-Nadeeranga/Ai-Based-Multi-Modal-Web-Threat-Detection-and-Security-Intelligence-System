import { Code2, Globe, Languages, Layers, LayoutTemplate } from 'lucide-react'

// Colour language: blue/cyan = info, amber = suspicious, red = malicious, green = legitimate.
// Values are C2 theme tokens (c2.css): light = 700-ish text on 50 tints, dark = 300 shades on slate-950;
// text is >= 4.5:1 in both themes. `hex` is a CSS colour for SVG strokes.
export const VERDICT_STYLE = {
  Legitimate: { text: 'text-[color:var(--c2-ok)]', ring: 'ring-[color:var(--c2-ok-ring-strong)]', bg: 'bg-[color:var(--c2-ok-tint)]', bar: 'bg-[color:var(--c2-ok-solid)]', hex: 'var(--c2-ok-solid)', label: 'Legitimate' },
  Suspicious: { text: 'text-[color:var(--c2-sus)]', ring: 'ring-[color:var(--c2-sus-ring-strong)]', bg: 'bg-[color:var(--c2-sus-tint)]', bar: 'bg-[color:var(--c2-sus-solid)]', hex: 'var(--c2-sus-solid)', label: 'Suspicious' },
  Malicious: { text: 'text-[color:var(--c2-mal)]', ring: 'ring-[color:var(--c2-mal-ring-strong)]', bg: 'bg-[color:var(--c2-mal-tint)]', bar: 'bg-[color:var(--c2-mal-solid)]', hex: 'var(--c2-mal-solid)', label: 'Malicious' },
  none: { text: 'text-[color:var(--c2-fg-2)]', ring: 'ring-[color:var(--c2-neutral-ring)]', bg: 'bg-[color:var(--c2-neutral-tint)]', bar: 'bg-[color:var(--c2-neutral-solid)]', hex: 'var(--c2-neutral-solid)', label: 'No verdict' },
}

export const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }
export const SEVERITY_STYLE = {
  critical: 'bg-[color:var(--c2-mal-tint-2)] text-[color:var(--c2-mal)] ring-[color:var(--c2-mal-ring)]',
  high: 'bg-[color:var(--c2-high-tint)] text-[color:var(--c2-high)] ring-[color:var(--c2-high-ring)]',
  medium: 'bg-[color:var(--c2-sus-tint)] text-[color:var(--c2-sus)] ring-[color:var(--c2-sus-ring)]',
  low: 'bg-[color:var(--c2-accent-tint)] text-[color:var(--c2-accent)] ring-[color:var(--c2-accent-ring-soft)]',
  info: 'bg-[color:var(--c2-neutral-tint-2)] text-[color:var(--c2-fg-2)] ring-[color:var(--c2-neutral-ring-soft)]',
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
