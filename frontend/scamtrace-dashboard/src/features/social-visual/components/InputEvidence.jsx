import { FileImage } from 'lucide-react'
import { Card } from './ui.jsx'

function Row({ label, children, mono = false }) {
  return (
    <div className="grid grid-cols-[110px_1fr] gap-3 py-2">
      <dt className="text-xs text-st-muted">{label}</dt>
      <dd className={`min-w-0 break-words text-sm text-st-ink ${mono ? 'font-mono' : ''}`}>{children}</dd>
    </div>
  )
}

export default function InputEvidence({ input, postImage }) {
  return (
    <Card title="Input evidence" icon={FileImage}>
      <div className="grid gap-5 sm:grid-cols-[160px_1fr]">
        {postImage
          ? <img src={postImage} alt="Submitted post" className="max-h-40 w-full rounded-lg bg-st-low object-contain ring-1 ring-st-container" />
          : <div className="flex h-28 items-center justify-center rounded-lg bg-st-low text-xs text-st-muted ring-1 ring-st-container">No image</div>}
        <dl className="divide-y divide-st-container">
          <Row label="Platform"><span className="capitalize">{input.platform}</span></Row>
          <Row label="Embedded URL" mono>{input.embedded_url || <span className="font-inter text-st-muted">—</span>}</Row>
          <Row label="Image file">{input.image_filename || <span className="text-st-muted">—</span>}</Row>
          <Row label="Post text">
            <span className="block max-h-28 overflow-auto whitespace-pre-wrap">
              {input.post_text || <span className="text-st-muted">—</span>}
            </span>
          </Row>
        </dl>
      </div>
    </Card>
  )
}
