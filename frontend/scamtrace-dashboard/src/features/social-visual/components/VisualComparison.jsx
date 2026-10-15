import { Images } from 'lucide-react'
import { Bar, Card, NotAvailable } from './ui.jsx'

export default function VisualComparison({ postImage, screenshot, visual }) {
  return (
    <Card title="Visual comparison" subtitle="Post image vs destination screenshot (CLIP image embeddings + pHash)" icon={Images}>
      {!visual ? <NotAvailable>Needs both a post image and a captured webpage.</NotAvailable> : (
        <>
          <div className="grid grid-cols-2 gap-4">
            <figure>
              <img src={postImage} alt="Post" className="w-full h-64 object-contain rounded-lg border border-st-container bg-st-low" />
              <figcaption className="mt-1 text-center text-xs text-st-muted">Post image</figcaption>
            </figure>
            <figure>
              <img src={screenshot} alt="Website" className="w-full h-64 object-contain rounded-lg border border-st-container bg-st-low" />
              <figcaption className="mt-1 text-center text-xs text-st-muted">Website screenshot</figcaption>
            </figure>
          </div>
          <div className="mt-4 space-y-3">
            <Bar label="CLIP visual similarity" value={visual.clip_cosine}
                 tone={visual.clip_cosine >= visual.low_threshold ? 'bg-emerald-500' : 'bg-red-500'}
                 hint={`Below ${(visual.low_threshold * 100).toFixed(0)}% is flagged as unrelated. pHash distance ${visual.phash_distance} / 64.`} />
            {visual.best_logo_pair_cosine !== null && <Bar label="Best post-logo ↔ website-logo similarity" value={visual.best_logo_pair_cosine} tone="bg-sky-500" />}
          </div>
        </>
      )}
    </Card>
  )
}
