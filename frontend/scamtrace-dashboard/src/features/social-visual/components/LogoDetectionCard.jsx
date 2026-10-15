import { ScanSearch } from 'lucide-react'
import { pct } from './constants.js'
import { Card, NotAvailable } from './ui.jsx'

function Detections({ title, image, detections, threshold }) {
  return (
    <div>
      <p className="text-xs font-semibold text-slate-300 mb-2">{title}</p>
      {!image ? <NotAvailable>Not available.</NotAvailable> : (
        <>
          <img src={image} alt={title} className="w-full max-h-96 object-contain rounded-lg border border-slate-800 bg-slate-950" />
          {detections.length === 0
            ? <p className="mt-2 text-xs text-slate-500">No logo regions detected.</p>
            : (
              <table className="mt-3 w-full text-xs">
                <thead className="text-slate-500"><tr><th className="text-left font-normal">Brand match</th><th className="text-right font-normal">Similarity</th><th className="text-right font-normal">Detector</th><th className="text-right font-normal">pHash</th></tr></thead>
                <tbody className="text-slate-200">
                  {detections.map((det, i) => (
                    <tr key={i} className="border-t border-slate-800">
                      <td className="py-1">{det.brand_id || <span className="text-slate-500">unknown (best {det.best_candidate})</span>}</td>
                      <td className="text-right font-mono">{pct(det.similarity, 1)}</td>
                      <td className="text-right font-mono">{pct(det.detector_confidence, 0)}</td>
                      <td className="text-right font-mono">{det.phash_distance}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          <p className="mt-1 text-[11px] text-slate-500">Brand accepted when CLIP crop similarity ≥ {pct(threshold)}; red boxes = accepted, yellow = unknown logo.</p>
        </>
      )}
    </div>
  )
}

export default function LogoDetectionCard({ logoDetection }) {
  return (
    <Card title="Logo detection" subtitle={`${logoDetection.detector} — boxes drawn by the backend on the analysed image`} icon={ScanSearch}>
      <div className="grid md:grid-cols-2 gap-6">
        <Detections title="Post image" image={logoDetection.annotated_image} detections={logoDetection.detections} threshold={logoDetection.threshold} />
        <Detections title="Website screenshot" image={logoDetection.website_annotated_image} detections={logoDetection.website_detections} threshold={logoDetection.threshold} />
      </div>
    </Card>
  )
}
