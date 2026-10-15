import { FileImage } from 'lucide-react'
import { Card, Field, NotAvailable } from './ui.jsx'

export default function InputEvidence({ input, postImage }) {
  return (
    <Card title="Input evidence" icon={FileImage}>
      <div className="grid md:grid-cols-[minmax(0,280px)_1fr] gap-6">
        {postImage
          ? <img src={postImage} alt="Submitted post" className="w-full rounded-lg border border-st-container bg-st-low object-contain max-h-80" />
          : <div className="rounded-lg border border-dashed border-st-container p-6"><NotAvailable>No post image submitted.</NotAvailable></div>}
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <Field label="Platform">{input.platform}</Field>
            <Field label="Image file">{input.image_filename}</Field>
          </div>
          <Field label="Embedded URL" mono>{input.embedded_url}</Field>
          <div>
            <p className="text-[11px] uppercase tracking-wide text-st-muted">Post text</p>
            <p className="mt-1 whitespace-pre-wrap text-sm text-st-ink rounded-lg bg-st-low border border-st-container p-3 max-h-48 overflow-auto">
              {input.post_text || <span className="italic text-st-muted">No post text submitted.</span>}
            </p>
          </div>
        </div>
      </div>
    </Card>
  )
}
