import { BadgeCheck } from 'lucide-react'
import { pct } from './constants.js'
import { Bar, Card, NotAvailable } from './ui.jsx'

function Candidates({ title, clip }) {
  if (!clip) return <div><p className="text-xs font-semibold text-st-ink mb-2">{title}</p><NotAvailable>Not available.</NotAvailable></div>
  return (
    <div>
      <p className="text-xs font-semibold text-st-ink">{title}</p>
      <p className="text-[11px] mb-3 text-st-muted">
        {clip.predicted_brand
          ? <>Accepted: <span className="text-st-ink">{clip.predicted_brand}</span> ({pct(clip.confidence, 1)} ≥ {pct(clip.threshold)})</>
          : <>Rejected as unknown brand (best {pct(clip.confidence, 1)} &lt; {pct(clip.threshold)})</>}
      </p>
      <div className="space-y-2">
        {clip.top_k.map((candidate) => (
          <Bar key={candidate.brand_id} label={candidate.name} value={candidate.probability}
               tone={candidate.brand_id === clip.predicted_brand ? 'bg-sky-500' : 'bg-st-outline'} />
        ))}
      </div>
    </div>
  )
}

export default function BrandAnalysisCard({ brandAnalysis, postImage, logoDetection }) {
  const reference = brandAnalysis?.reference_logo
  const post = brandAnalysis?.post_image
  const bestLogo = (logoDetection?.detections || []).find((det) => det.best_candidate === reference?.brand_id)
  const clipRow = post?.top_k.find((candidate) => candidate.brand_id === reference?.brand_id)

  return (
    <Card title="Brand analysis" subtitle={`CLIP ViT-B/16 zero-shot, ${post?.mode || 'fused'} mode, ${pct(post?.threshold)} acceptance threshold`} icon={BadgeCheck}>
      <div className="grid md:grid-cols-2 gap-6">
        <Candidates title="Post image — top candidates" clip={post} />
        <Candidates title="Website screenshot — top candidates" clip={brandAnalysis?.website} />
      </div>
      {reference && postImage && (
        <div className="mt-6 border-t border-st-container pt-4">
          <p className="text-xs font-semibold text-st-ink mb-3">
            Post image vs reference logo ({reference.name}{post?.predicted_brand === reference.brand_id ? '' : ' — best candidate, not accepted'})
          </p>
          <div className="flex flex-wrap items-center gap-6">
            <img src={postImage} alt="Post" className="h-32 rounded border border-st-container bg-st-low object-contain" />
            <span className="text-st-muted">↔</span>
            <img src={reference.image} alt={reference.name} className="h-32 w-32 rounded border border-st-container bg-white object-contain" />
            <div className="text-sm space-y-1">
              <p className="text-st-muted">CLIP logo cosine: <span className="font-mono text-st-ink">{clipRow ? clipRow.logo_cosine.toFixed(3) : '—'}</span></p>
              <p className="text-st-muted">CLIP text cosine: <span className="font-mono text-st-ink">{clipRow ? clipRow.text_cosine.toFixed(3) : '—'}</span></p>
              <p className="text-st-muted">Detected logo similarity: <span className="font-mono text-st-ink">{bestLogo ? pct(bestLogo.similarity, 1) : '—'}</span></p>
            </div>
          </div>
        </div>
      )}
    </Card>
  )
}
