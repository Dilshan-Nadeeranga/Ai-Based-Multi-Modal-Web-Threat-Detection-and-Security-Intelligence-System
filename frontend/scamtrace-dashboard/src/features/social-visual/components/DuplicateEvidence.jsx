import { Copy } from 'lucide-react'
import { Card, Field, NotAvailable } from './ui.jsx'

export default function DuplicateEvidence({ preprocessing }) {
  const duplicate = preprocessing?.duplicate
  return (
    <Card title="Duplicate evidence" subtitle="Perceptual hash compared with the stored image hashes" icon={Copy}>
      {!duplicate ? <NotAvailable>No valid post image.</NotAvailable> : (
        <div className="grid grid-cols-2 gap-4">
          <Field label="pHash" mono>{preprocessing.phash}</Field>
          <Field label="Duplicate status">
            <span className={duplicate.is_duplicate ? 'text-amber-700 font-semibold' : 'text-emerald-700 font-semibold'}>
              {duplicate.is_duplicate ? `${duplicate.duplicate_type} duplicate` : 'No duplicate'}
            </span>
          </Field>
          <Field label="Matched sample" mono>{duplicate.matched_sample_id}</Field>
          <Field label="Hamming distance">
            {duplicate.hash_distance ?? '—'} <span className="text-st-muted">(threshold ≤ {duplicate.threshold})</span>
          </Field>
          <p className="col-span-2 text-[11px] text-st-muted">Compared against {duplicate.compared_against} stored hashes. The live upload is not added to the hash store.</p>
        </div>
      )}
    </Card>
  )
}
