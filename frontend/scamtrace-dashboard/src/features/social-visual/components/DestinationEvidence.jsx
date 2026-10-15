import { Globe } from 'lucide-react'
import { Card, Field, NotAvailable } from './ui.jsx'

export default function DestinationEvidence({ destination, step }) {
  return (
    <Card title="Destination evidence" subtitle="Sandboxed headless-browser capture of the embedded URL" icon={Globe}>
      {!destination ? (
        <NotAvailable>{step?.status === 'failed' ? `Capture failed: ${step.detail}` : 'No embedded URL submitted.'}</NotAvailable>
      ) : (
        <div className="grid md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] gap-6">
          {destination.screenshot
            ? <img src={destination.screenshot} alt="Destination webpage" className="w-full rounded-lg border border-slate-800 bg-slate-950" />
            : <NotAvailable>No screenshot ({destination.error_code || 'unknown error'}).</NotAvailable>}
          <div className="space-y-3">
            <Field label="Original URL" mono>{destination.original_url}</Field>
            {destination.short_link && (
              <p className={`text-xs ${destination.short_link.resolved ? 'text-emerald-400' : 'text-amber-400'}`}>
                {destination.short_link.resolved
                  ? `Short link expanded with plain HTTP redirects (${destination.short_link.hops.length} hop(s)) before the browser capture.`
                  : `Short link could not be expanded without a browser (${destination.short_link.stopped_reason || 'no redirect'}); the shortener page itself was captured.`}
              </p>
            )}
            <Field label="Final URL" mono>{destination.final_url}</Field>
            <div className="grid grid-cols-2 gap-4">
              <Field label="Final domain" mono>{destination.final_domain}</Field>
              <Field label="HTTP status">{destination.http_status}</Field>
            </div>
            <Field label="Page title">{destination.page_title}</Field>
            {destination.redirect_chain?.length > 1 && (
              <div>
                <p className="text-[11px] uppercase tracking-wide text-slate-500">Redirect chain</p>
                <ol className="mt-1 space-y-0.5 text-xs font-mono text-slate-300">
                  {destination.redirect_chain.map((hop, i) => <li key={i} className="break-all">{hop.status ?? '—'} {hop.url}</li>)}
                </ol>
              </div>
            )}
            {destination.error_message && <p className="text-xs text-amber-400">{destination.error_code}: {destination.error_message}</p>}
            <p className="text-[11px] text-slate-500">{destination.blocked_requests} request(s) blocked by the capture safety proxy.</p>
          </div>
        </div>
      )}
    </Card>
  )
}
