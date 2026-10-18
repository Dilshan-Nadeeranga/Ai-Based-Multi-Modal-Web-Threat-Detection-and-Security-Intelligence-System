import { useEffect, useState } from 'react'
import { Database, Loader2 } from 'lucide-react'
import { getDatasetOverview, getDatasetStatistics } from '../api/socialVisualApi.js'
import { Card } from './ui.jsx'

const SPLITS = ['train', 'val', 'test']
const SPLIT_NAMES = { train: 'Train', val: 'Validation', test: 'Test' }

function formatDate(value) {
  const date = value ? new Date(value) : null
  return date && !Number.isNaN(date.getTime()) ? date.toLocaleString() : value
}

function Section({ title, children }) {
  return (
    <div className="mt-4">
      <p className="mb-2 text-[11px] uppercase tracking-wide text-st-muted">{title}</p>
      {children}
    </div>
  )
}

function CountChips({ data }) {
  return (
    <div className="flex flex-wrap gap-2">
      {Object.entries(data || {}).map(([key, value]) => (
        <span key={key} className="inline-flex items-center gap-2 rounded-full bg-st-low px-3 py-1 text-xs text-st-ink ring-1 ring-st-container">
          {key.replaceAll('_', ' ')}
          <span className="font-mono font-semibold text-st-blue-dark">{value}</span>
        </span>
      ))}
    </div>
  )
}

function BrandSplits({ brands }) {
  return (
    <div className="space-y-3">
      {SPLITS.filter((split) => brands[split]?.length).map((split) => (
        <div key={split}>
          <p className="mb-1.5 text-xs font-semibold text-st-navy">
            {SPLIT_NAMES[split]} <span className="font-normal text-st-muted">· {brands[split].length} brands</span>
          </p>
          <div className="flex flex-wrap gap-1.5">
            {brands[split].map((brand) => (
              <span key={brand} className="rounded-md bg-st-low px-2 py-0.5 text-[11px] text-st-ink ring-1 ring-st-container">{brand}</span>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

function Distribution({ title, data, includeZero = false, hide = [] }) {
  const entries = Object.entries(data || {})
    .filter(([key, value]) => typeof value === 'number' && !hide.includes(key) && (includeZero || value > 0))
  const max = Math.max(1, ...entries.map(([, value]) => value))
  return (
    <Card title={title}>
      <div className="space-y-2">
        {entries.map(([key, value]) => (
          <div key={key}>
            <div className="flex justify-between text-xs text-st-ink">
              <span>{key.replaceAll('_', ' ')}</span>
              <span className={`font-mono ${value === 0 ? 'text-st-muted' : ''}`}>{value === 0 ? '0 (no samples)' : value}</span>
            </div>
            <div className="mt-1 h-2 rounded bg-st-container overflow-hidden"><div className="st-bar h-full bg-sky-500" style={{ width: `${(value / max) * 100}%` }} /></div>
          </div>
        ))}
        {entries.length === 0 && <p className="text-sm text-st-muted">No data.</p>}
      </div>
    </Card>
  )
}

function Tiles({ items }) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
      {items.map(([label, value]) => (
        <div key={label} className="rounded-lg bg-st-low border border-st-container p-3">
          <p className="text-[11px] uppercase text-st-muted">{label}</p>
          <p className="text-xl font-bold text-st-ink">{value ?? '—'}</p>
        </div>
      ))}
    </div>
  )
}

function SplitTable({ title, subtitle, counts }) {
  if (!counts) {
    return <Card title={title} subtitle={subtitle}><p className="text-sm text-st-muted">Not available.</p></Card>
  }
  const labels = [...new Set(SPLITS.flatMap((split) => Object.keys(counts[split] || {})))]
  const total = (label) => SPLITS.reduce((sum, split) => sum + (counts[split]?.[label] || 0), 0)
  return (
    <Card title={title} subtitle={subtitle}>
      <table className="w-full text-xs text-st-ink">
        <thead>
          <tr className="text-st-muted">
            <th className="text-left font-normal pb-1">Label</th>
            {SPLITS.map((split) => <th key={split} className="text-right font-normal pb-1">{split}</th>)}
            <th className="text-right font-normal pb-1">total</th>
          </tr>
        </thead>
        <tbody>
          {labels.map((label) => (
            <tr key={label} className="border-t border-st-container">
              <td className="py-1">{label.replaceAll('_', ' ')}</td>
              {SPLITS.map((split) => <td key={split} className="py-1 text-right font-mono">{counts[split]?.[label] ?? 0}</td>)}
              <td className="py-1 text-right font-mono font-semibold">{total(label)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  )
}

function LogoDetectorCard({ logo }) {
  if (!logo) return <Card title="Logo detector training set"><p className="text-sm text-st-muted">Not available.</p></Card>
  const cell = (split, source, key) => logo.counts?.[split]?.[source]?.[key] ?? 0
  return (
    <Card title="Logo detector training set (YOLO)" subtitle={`Classes: ${(logo.classes || []).join(', ')} · ${logo.dom_box_kinds_note || ''}`}>
      <table className="w-full text-xs text-st-ink">
        <thead>
          <tr className="text-st-muted">
            <th className="text-left font-normal pb-1">Split</th>
            <th className="text-right font-normal pb-1">Real-page images</th>
            <th className="text-right font-normal pb-1">Real-page boxes</th>
            <th className="text-right font-normal pb-1">Generated images</th>
            <th className="text-right font-normal pb-1">Generated boxes</th>
          </tr>
        </thead>
        <tbody>
          {SPLITS.map((split) => (
            <tr key={split} className="border-t border-st-container">
              <td className="py-1">{split}</td>
              <td className="py-1 text-right font-mono">{cell(split, 'dom', 'images')}</td>
              <td className="py-1 text-right font-mono">{cell(split, 'dom', 'boxes')}</td>
              <td className="py-1 text-right font-mono">{cell(split, 'synthetic', 'images')}</td>
              <td className="py-1 text-right font-mono">{cell(split, 'synthetic', 'boxes')}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {logo.dom_page_labels && (
        <Section title="Real webpages"><CountChips data={logo.dom_page_labels} /></Section>
      )}
      {logo.synthetic_brands_by_split && (
        <Section title="Generated-image brands by split"><BrandSplits brands={logo.synthetic_brands_by_split} /></Section>
      )}
    </Card>
  )
}

function ExternalDatasetCard({ title, data }) {
  const excluded = Object.entries(data.excluded || {}).map(([k, v]) => [k.replace(/^excluded_/, '').replaceAll('_', ' '), v])
  const brands = data.brand_summary || {}
  return (
    <Card title={title} subtitle={`${data.source} · ${data.label_basis} · kept apart from the multimodal dataset above`}>
      <div className="grid md:grid-cols-2 gap-6">
        <div>
          <Distribution title="Imported samples by category" data={data.categories} includeZero />
          {data.category_note && <p className="mt-2 text-[11px] text-st-muted">{data.category_note}</p>}
        </div>
        <div className="space-y-4">
          {brands.distinct_brands !== undefined && (
            <Section title="Brand impersonation coverage">
              <CountChips data={{ 'distinct brands': brands.distinct_brands, 'catalog brands covered': brands.catalog_brands_covered,
                'messages for catalog brands': brands.messages_for_catalog_brands }} />
            </Section>
          )}
          {data.brand_impersonation_by_brand && Object.keys(data.brand_impersonation_by_brand).length > 0 && (
            <Section title={brands.distinct_brands !== undefined ? 'Most impersonated brands' : 'Impersonated brands'}>
              <CountChips data={data.brand_impersonation_by_brand} />
            </Section>
          )}
          {data.url_types && <Section title="URL types"><CountChips data={data.url_types} /></Section>}
          {excluded.length > 0 && (
            <Section title="Excluded"><CountChips data={Object.fromEntries(excluded)} /></Section>
          )}
          <Section title="Use">
            <p className="text-xs text-st-muted">
              {data.used_in_training ? 'Used in training.' : 'Not used in the deployed models.'}
              {data.experiment_decision ? ` ${data.experiment_decision}.` : ''}
            </p>
          </Section>
          <Section title="Licence">
            <p className="text-xs text-st-muted">{data.licence}</p>
          </Section>
        </div>
      </div>
    </Card>
  )
}

export default function DatasetTab() {
  const [stats, setStats] = useState(null)
  const [overview, setOverview] = useState(null)
  const [error, setError] = useState('')
  const [overviewError, setOverviewError] = useState('')

  useEffect(() => {
    getDatasetStatistics().then(setStats).catch((err) => setError(err.message))
    getDatasetOverview().then(setOverview).catch((err) => setOverviewError(err.message))
  }, [])

  if (error) return <p role="alert" className="rounded-lg bg-st-error-bg p-4 text-sm text-st-error-ink">{error}</p>
  if (!stats) return <p className="flex items-center gap-2 text-sm text-st-muted"><Loader2 className="w-4 h-4 animate-spin" /> Loading dataset statistics…</p>

  const totals = [
    ['Samples', stats.total_samples], ['Verified labels', stats.label_status?.verified],
    ['Images', stats.total_images], ['Embedded URLs', stats.total_embedded_urls],
    ['Samples with text', stats.samples_with_text], ['Web captures', stats.web_captures?.captured],
  ]
  const coverage = [
    ['With images', stats.samples_with_images], ['Without images', stats.samples_without_images],
    ['With URLs', stats.samples_with_urls], ['Without URLs', stats.samples_without_urls],
    ['Claimed brand', stats.samples_with_claimed_brand], ['Synthetic excluded', stats.excluded_synthetic_samples],
  ]
  const captures = stats.web_captures || {}
  const brand = overview?.brand_reference
  const splits = overview?.training_splits || {}

  return (
    <div className="space-y-6">
      <Card title="C3 multimodal dataset" subtitle={`Version ${stats.dataset_version} · generated ${formatDate(stats.generated_at)}`} icon={Database}>
        <Tiles items={totals} />
        <Section title="Coverage"><Tiles items={coverage} /></Section>
      </Card>

      <div className="grid md:grid-cols-2 gap-6">
        <Distribution title="Binary scam labels" data={stats.binary_labels} hide={['not_annotated']} />
        <Distribution title="Scam type" data={stats.class_distribution} includeZero hide={['unknown']} />
        <Distribution title="Misinformation labels (Fakeddit)" data={stats.misinformation_labels} hide={['not_annotated']} />
        <Distribution title="Misinformation type" data={stats.misinformation_type_distribution} hide={['unknown']} />
        <Distribution title="Scam label status" data={stats.label_status} includeZero hide={['not_annotated']} />
        <Distribution title="Misinformation label status" data={stats.misinformation_label_status} includeZero hide={['not_annotated']} />
        <Distribution title="Platform" data={stats.platform_distribution} />
        <Distribution title="Collection method" data={stats.collection_method_distribution} />
      </div>

      <Card title="Destination webpage captures" subtitle="Embedded URLs captured in the sandboxed browser">
        <Tiles items={[
          ['Attempts', captures.attempts], ['Captured', captures.captured], ['HTTP errors', captures.http_error],
          ['Failed', captures.failed], ['Redirected', captures.redirected_captures], ['Not yet captured', captures.samples_with_urls_not_captured],
        ]} />
        {captures.error_codes && (
          <Section title="Capture error codes">
            <CountChips data={Object.fromEntries(Object.entries(captures.error_codes).map(([k, v]) => [k.toLowerCase(), v]))} />
          </Section>
        )}
      </Card>

      {overviewError && <p role="alert" className="rounded-lg bg-st-error-bg p-4 text-sm text-st-error-ink">{overviewError}</p>}
      {overview && (
        <>
          <Card title="Brand reference dataset" subtitle={brand ? `Generated ${formatDate(brand.generated_at)}` : undefined}>
            {brand ? (
              <>
                <Tiles items={[
                  ['Brands', brand.brands_in_catalog], ['Logos', brand.primary_logos_on_disk], ['Normalized logos', brand.normalized_logos_on_disk],
                  ['Website screenshots', brand.screenshots_on_disk], ['Logo annotations', brand.logo_annotations], ['Bounding boxes', brand.logo_boxes],
                ]} />
                <Section title="Brand split">
                  <CountChips data={Object.fromEntries(Object.entries(brand.split_counts || {}).map(([k, v]) => [SPLIT_NAMES[k] || k, v]))} />
                </Section>
              </>
            ) : <p className="text-sm text-st-muted">Not available.</p>}
          </Card>
          <div className="grid md:grid-cols-2 gap-6">
            <Distribution title="Brand categories" data={brand?.categories} />
            <LogoDetectorCard logo={overview.logo_detector} />
          </div>

          <div className="grid md:grid-cols-3 gap-6">
            <SplitTable title="Text baseline splits" subtitle="Binary scam model" counts={splits.text_baseline} />
            <SplitTable title="Threat category splits" subtitle="Four-class category model" counts={splits.threat_category} />
            <SplitTable title="Misinformation splits" subtitle="Fakeddit, stratified by fake type" counts={splits.misinformation} />
          </div>

          {overview.external?.smishtank && (
            <ExternalDatasetCard title="External dataset: Smishtank (reported scam SMS)" data={overview.external.smishtank} />
          )}
          {overview.external?.telephish && (
            <ExternalDatasetCard title="External dataset: TelePhish (Telegram)" data={overview.external.telephish} />
          )}
        </>
      )}
    </div>
  )
}
