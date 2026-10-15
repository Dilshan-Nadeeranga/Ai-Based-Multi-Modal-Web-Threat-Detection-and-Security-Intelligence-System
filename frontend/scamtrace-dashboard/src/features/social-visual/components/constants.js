export const LEVEL_STYLES = {
  LOW: { text: 'text-emerald-700', bg: 'bg-emerald-500', border: 'border-emerald-200', soft: 'bg-emerald-50' },
  MEDIUM: { text: 'text-orange-700', bg: 'bg-orange-500', border: 'border-orange-200', soft: 'bg-orange-50' },
  HIGH: { text: 'text-red-700', bg: 'bg-red-500', border: 'border-red-200', soft: 'bg-red-50' },
}

export const PIPELINE_STEPS = [
  { key: 'preprocessing', label: 'Image preprocessing' },
  { key: 'ocr', label: 'OCR extraction' },
  { key: 'text_threat', label: 'Text threat analysis' },
  { key: 'brand_analysis', label: 'Brand analysis (CLIP)' },
  { key: 'logo_detection', label: 'Logo detection (YOLO)' },
  { key: 'web_capture', label: 'Destination webpage capture' },
  { key: 'visual_similarity', label: 'Visual similarity' },
  { key: 'consistency', label: 'Cross-source consistency' },
  { key: 'risk_fusion', label: 'Preliminary risk fusion' },
  { key: 'threat_classification', label: 'Threat category classification' },
]

export function pct(value, digits = 0) {
  return value === null || value === undefined ? '—' : `${(value * 100).toFixed(digits)}%`
}
