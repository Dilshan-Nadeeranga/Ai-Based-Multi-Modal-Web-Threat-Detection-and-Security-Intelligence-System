import { useEffect, useMemo, useState } from 'react'
import { BarChart3, Database, DownloadCloud, ImagePlus, Link2, Loader2, PencilLine, Search } from 'lucide-react'
import AppShell from '../../../components/AppShell.jsx'
import { analyzePost, dataUrlToFile, fetchSocialPost } from '../api/socialVisualApi.js'
import AnalysisProgress from '../components/AnalysisProgress.jsx'
import BrandAnalysisCard from '../components/BrandAnalysisCard.jsx'
import ConsistencyAnalysis from '../components/ConsistencyAnalysis.jsx'
import DatasetTab from '../components/DatasetTab.jsx'
import DestinationEvidence from '../components/DestinationEvidence.jsx'
import DuplicateEvidence from '../components/DuplicateEvidence.jsx'
import EvidenceSummary from '../components/EvidenceSummary.jsx'
import InputEvidence from '../components/InputEvidence.jsx'
import LogoDetectionCard from '../components/LogoDetectionCard.jsx'
import ModelResultsTab from '../components/ModelResultsTab.jsx'
import OCRAnalysisCard from '../components/OCRAnalysisCard.jsx'
import RiskBreakdown from '../components/RiskBreakdown.jsx'
import TextThreatCard from '../components/TextThreatCard.jsx'
import ThreatCategoryCard from '../components/ThreatCategoryCard.jsx'
import ThreatAssessment from '../components/ThreatAssessment.jsx'
import VisualComparison from '../components/VisualComparison.jsx'

const TABS = [
  { id: 'analyze', label: 'Analyze Post', icon: Search },
  { id: 'dataset', label: 'Dataset', icon: Database },
  { id: 'models', label: 'Model Results', icon: BarChart3 },
]
const PLATFORMS = ['facebook', 'instagram', 'x', 'tiktok', 'whatsapp', 'telegram', 'reddit', 'linkedin', 'youtube', 'other']

const inputClass = 'st-autofill w-full rounded-lg bg-st-low/60 px-3 py-2.5 text-sm text-st-navy outline-none ring-1 ring-st-container transition placeholder:text-st-outline focus:bg-white focus:ring-2 focus:ring-st-blue-dark'
const labelClass = 'text-xs font-bold uppercase tracking-wider text-st-muted'
const cardClass = 'rounded-xl bg-white p-6 shadow-sm ring-1 ring-st-container/60'
const primaryButton = 'flex items-center justify-center gap-2 rounded-lg bg-st-navy px-5 py-2.5 text-sm font-semibold text-white shadow-md shadow-st-navy/20 transition hover:bg-st-blue-dark disabled:cursor-not-allowed disabled:opacity-50'

export default function SocialVisualAnalysis() {
  const [tab, setTab] = useState('analyze')
  const [platform, setPlatform] = useState('facebook')
  const [postText, setPostText] = useState('')
  const [embeddedUrl, setEmbeddedUrl] = useState('')
  const [image, setImage] = useState(null)
  const [postUrl, setPostUrl] = useState('')
  const [fetching, setFetching] = useState(false)
  const [fetched, setFetched] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)

  const preview = useMemo(() => (image ? URL.createObjectURL(image) : null), [image])
  useEffect(() => () => preview && URL.revokeObjectURL(preview), [preview])

  async function runAnalysis(input) {
    setResult(null)
    setLoading(true)
    try {
      setResult(await analyzePost(input))
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  function handleSubmit(event) {
    event.preventDefault()
    setError('')
    runAnalysis({ platform, postText, image, embeddedUrl })
  }

  async function handleFetch(event) {
    event.preventDefault()
    setError('')
    setResult(null)
    setFetched(null)
    setFetching(true)
    let input
    try {
      const post = await fetchSocialPost(postUrl.trim())
      const file = post.image ? await dataUrlToFile(post.image.data_url, post.image.filename) : null
      input = { platform: post.platform, postText: post.post_text, image: file, embeddedUrl: post.embedded_url || '' }
      setPlatform(input.platform)
      setPostText(input.postText)
      setEmbeddedUrl(input.embeddedUrl)
      setImage(file)
      setFetched(post)
    } catch (err) {
      setError(err.message)
      return
    } finally {
      setFetching(false)
    }
    runAnalysis(input)
  }

  const busy = loading || fetching
  const canSubmit = !busy && (postText.trim() || image || embeddedUrl.trim())
  const captureStep = result?.pipeline.find((step) => step.key === 'web_capture')

  return (
    <AppShell title="Social Visual Analysis">
      <div className="flex w-full flex-col gap-6 px-4 py-8 md:px-8">
        <header className="flex flex-col gap-1">
          <span className="w-fit rounded-full bg-st-container px-2 py-0.5 text-[0.6875rem] font-bold uppercase tracking-widest text-st-blue-dark">
            Component C3
          </span>
          <h1 className="font-manrope text-[1.75rem] font-bold tracking-tight text-st-navy lg:text-4xl">Social Media &amp; Web Visual Threat Analyzer</h1>
          <p className="max-w-3xl text-base text-st-muted">
            Analyze multimodal evidence from social media posts: text, images, logos, brands and the linked web page.
          </p>
        </header>

        <nav className="flex w-fit flex-wrap gap-1 rounded-lg bg-white p-1 shadow-sm ring-1 ring-st-container/60" role="tablist">
          {TABS.map(({ id, label, icon: Icon }) => (
            <button key={id} type="button" role="tab" aria-selected={tab === id} onClick={() => setTab(id)}
                    className={`flex items-center gap-1.5 rounded-md px-4 py-2 text-sm font-semibold transition ${tab === id
                      ? 'bg-st-navy-2 text-white shadow-sm' : 'text-st-muted hover:bg-st-container hover:text-st-navy'}`}>
              <Icon className="h-4 w-4" aria-hidden="true" /> {label}
            </button>
          ))}
        </nav>

        {tab === 'dataset' && <DatasetTab />}
        {tab === 'models' && <ModelResultsTab />}

        {tab === 'analyze' && (
          <>
            <form onSubmit={handleFetch} className={`${cardClass} space-y-3`}>
              <div className="flex items-start gap-3">
                <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-st-low text-st-blue-dark">
                  <Link2 className="h-5 w-5" aria-hidden="true" />
                </span>
                <div>
                  <h2 className="font-manrope text-lg font-semibold text-st-navy">Fetch a Social Post</h2>
                  <p className="text-xs text-st-muted">Paste a public Reddit or Facebook post URL to extract and analyze it automatically.</p>
                </div>
              </div>
              <label className="block">
                <span className={labelClass}>Social post URL (Reddit or Facebook)</span>
                <div className="mt-1 flex flex-col sm:flex-row gap-3">
                  <input type="text" value={postUrl} onChange={(e) => setPostUrl(e.target.value)}
                         placeholder="https://www.reddit.com/r/Scams/comments/... or https://www.facebook.com/<page>/posts/..."
                         className={`flex-1 font-mono ${inputClass}`} />
                  <button type="submit" disabled={busy || !postUrl.trim()} className={primaryButton}>
                    {fetching ? <Loader2 className="w-4 h-4 animate-spin" /> : <DownloadCloud className="w-4 h-4" />} Fetch &amp; Analyze
                  </button>
                </div>
              </label>
              <p className="text-[11px] text-st-muted">
                {fetching ? 'Opening the post and extracting its text, embedded URL and image…'
                  : 'Extracts the post text, embedded URL and image, fills the fields below and runs the analysis. '
                    + 'Facebook works only for public posts visible without login. You can also fill the fields manually.'}
              </p>
              {fetched && (
                <p className="rounded-lg bg-st-low px-3 py-2 text-xs text-st-ink">
                  Fetched {fetched.platform} · <span className="font-semibold text-st-navy">{fetched.source_name}</span> · {fetched.post_type} post ·{' '}
                  {fetched.post_text ? 'text extracted' : 'no text'} · {fetched.image ? 'image extracted' : 'no image'} ·{' '}
                  {fetched.embedded_urls.length} embedded URL(s) ·{' '}
                  <a href={fetched.permalink} target="_blank" rel="noreferrer" className="font-semibold text-st-blue-dark hover:underline">open post</a>
                </p>
              )}
            </form>

            <form onSubmit={handleSubmit} className={`${cardClass} space-y-5`}>
              <div className="flex items-start gap-3">
                <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-st-low text-st-blue-dark">
                  <PencilLine className="h-5 w-5" aria-hidden="true" />
                </span>
                <div>
                  <h2 className="font-manrope text-lg font-semibold text-st-navy">Enter Post Details</h2>
                  <p className="text-xs text-st-muted">Provide the post text, an image, an embedded URL, or any combination.</p>
                </div>
              </div>
              <div className="grid md:grid-cols-[1fr_280px] gap-6">
                <div className="space-y-4">
                  <label className="block">
                    <span className={labelClass}>Platform</span>
                    <select value={platform} onChange={(e) => setPlatform(e.target.value)} className={`mt-1 capitalize ${inputClass}`}>
                      {PLATFORMS.map((p) => <option key={p} value={p}>{p}</option>)}
                    </select>
                  </label>
                  <label className="block">
                    <span className={labelClass}>Post text</span>
                    <textarea rows={5} value={postText} onChange={(e) => setPostText(e.target.value)}
                              placeholder="Paste the caption / message of the post" className={`mt-1 ${inputClass}`} />
                  </label>
                  <label className="block">
                    <span className={labelClass}>Embedded URL</span>
                    <input type="text" value={embeddedUrl} onChange={(e) => setEmbeddedUrl(e.target.value)}
                           placeholder="https://example.com/..." className={`mt-1 font-mono ${inputClass}`} />
                  </label>
                </div>
                <div className="flex flex-col gap-4">
                  <label className="flex-1 flex flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed border-st-outline/60 bg-st-low/60 hover:border-st-blue hover:bg-st-low p-4 cursor-pointer text-center transition">
                    {preview
                      ? <img src={preview} alt="Selected post" className="max-h-48 rounded object-contain" />
                      : <><ImagePlus className="w-8 h-8 text-st-blue-dark" /><span className="text-sm font-semibold text-st-navy">Upload post image</span></>}
                    <span className="text-[11px] text-st-muted break-all">{image ? image.name : 'JPEG, PNG, WebP'}</span>
                    <input type="file" accept="image/*" className="hidden" onChange={(e) => setImage(e.target.files?.[0] || null)} />
                  </label>
                  {image && <button type="button" onClick={() => setImage(null)} className="text-xs font-semibold text-st-muted hover:text-st-error">Remove image</button>}
                  <button type="submit" disabled={!canSubmit} className={`${primaryButton} py-3`}>
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />} Analyze Post
                  </button>
                </div>
              </div>
            </form>

            {error && <p role="alert" className="rounded-lg bg-st-error-bg p-4 text-sm text-st-error-ink">{error}</p>}
            {(loading || result) && <AnalysisProgress running={loading} pipeline={result?.pipeline} />}

            {result && (
              <div className="space-y-6">
                <ThreatAssessment assessment={result.assessment} disclaimer={result.disclaimer} />
                <ThreatCategoryCard classification={result.classification} />
                <InputEvidence input={result.input} postImage={result.post_image} />
                <div className="grid lg:grid-cols-2 gap-6">
                  <OCRAnalysisCard ocr={result.ocr} preprocessing={result.preprocessing} />
                  <DuplicateEvidence preprocessing={result.preprocessing} />
                </div>
                <TextThreatCard textThreat={result.text_threat} />
                <BrandAnalysisCard brandAnalysis={result.brand_analysis} postImage={result.post_image} logoDetection={result.logo_detection} />
                <LogoDetectionCard logoDetection={result.logo_detection} />
                <DestinationEvidence destination={result.destination} step={captureStep} />
                <VisualComparison postImage={result.post_image} screenshot={result.destination?.screenshot} visual={result.visual_similarity} />
                <ConsistencyAnalysis consistency={result.consistency} />
                <RiskBreakdown risk={result.risk} />
                <EvidenceSummary assessment={result.assessment} />
              </div>
            )}
          </>
        )}
      </div>
    </AppShell>
  )
}
