import { useEffect, useMemo, useState } from 'react'
import { DownloadCloud, ImagePlus, Loader2, Search } from 'lucide-react'
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
  { id: 'analyze', label: 'Analyze Post' },
  { id: 'dataset', label: 'Dataset' },
  { id: 'models', label: 'Model Results' },
]
const PLATFORMS = ['facebook', 'instagram', 'x', 'tiktok', 'whatsapp', 'telegram', 'reddit', 'linkedin', 'youtube', 'other']

const inputClass = 'w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 focus:outline-none focus:border-sky-500'

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
    <main className="flex-1 w-full bg-slate-950 text-slate-100">
      <div className="max-w-6xl mx-auto px-4 py-10 space-y-6">
        <header>
          <p className="text-xs font-semibold uppercase tracking-widest text-sky-400">ScamTrace</p>
          <h1 className="text-2xl font-bold">Social Media &amp; Web Visual Threat Analyzer</h1>
          <p className="text-sm text-slate-400">Analyze multimodal evidence from social-media posts</p>
        </header>

        <nav className="flex gap-1 border-b border-slate-800">
          {TABS.map(({ id, label }) => (
            <button key={id} type="button" onClick={() => setTab(id)}
                    className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px ${tab === id
                      ? 'border-sky-500 text-white' : 'border-transparent text-slate-400 hover:text-slate-200'}`}>
              {label}
            </button>
          ))}
        </nav>

        {tab === 'dataset' && <DatasetTab />}
        {tab === 'models' && <ModelResultsTab />}

        {tab === 'analyze' && (
          <>
            <form onSubmit={handleFetch} className="bg-slate-900/80 border border-sky-900/70 rounded-xl p-6 space-y-3">
              <label className="block">
                <span className="text-xs uppercase tracking-wide text-slate-400">Social post URL (Reddit or Facebook)</span>
                <div className="mt-1 flex flex-col sm:flex-row gap-3">
                  <input type="text" value={postUrl} onChange={(e) => setPostUrl(e.target.value)}
                         placeholder="https://www.reddit.com/r/Scams/comments/... or https://www.facebook.com/<page>/posts/..."
                         className={`flex-1 font-mono ${inputClass}`} />
                  <button type="submit" disabled={busy || !postUrl.trim()}
                          className="flex items-center justify-center gap-2 rounded-lg bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 disabled:text-slate-400 px-5 py-2 text-sm font-bold tracking-wide">
                    {fetching ? <Loader2 className="w-4 h-4 animate-spin" /> : <DownloadCloud className="w-4 h-4" />} FETCH &amp; ANALYZE
                  </button>
                </div>
              </label>
              <p className="text-[11px] text-slate-500">
                {fetching ? 'Opening the post and extracting its text, embedded URL and image…'
                  : 'Extracts the post text, embedded URL and image, fills the fields below and runs the analysis. '
                    + 'Facebook works only for public posts visible without login. You can also fill the fields manually.'}
              </p>
              {fetched && (
                <p className="text-xs text-slate-300">
                  Fetched {fetched.platform} · <span className="text-slate-100 font-semibold">{fetched.source_name}</span> · {fetched.post_type} post ·{' '}
                  {fetched.post_text ? 'text extracted' : 'no text'} · {fetched.image ? 'image extracted' : 'no image'} ·{' '}
                  {fetched.embedded_urls.length} embedded URL(s) ·{' '}
                  <a href={fetched.permalink} target="_blank" rel="noreferrer" className="text-sky-400 hover:underline">open post</a>
                </p>
              )}
            </form>

            <form onSubmit={handleSubmit} className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 grid md:grid-cols-[1fr_260px] gap-6">
              <div className="space-y-4">
                <label className="block">
                  <span className="text-xs uppercase tracking-wide text-slate-400">Platform</span>
                  <select value={platform} onChange={(e) => setPlatform(e.target.value)} className={`mt-1 ${inputClass}`}>
                    {PLATFORMS.map((p) => <option key={p} value={p}>{p}</option>)}
                  </select>
                </label>
                <label className="block">
                  <span className="text-xs uppercase tracking-wide text-slate-400">Post text</span>
                  <textarea rows={5} value={postText} onChange={(e) => setPostText(e.target.value)}
                            placeholder="Paste the caption / message of the post" className={`mt-1 ${inputClass}`} />
                </label>
                <label className="block">
                  <span className="text-xs uppercase tracking-wide text-slate-400">Embedded URL</span>
                  <input type="text" value={embeddedUrl} onChange={(e) => setEmbeddedUrl(e.target.value)}
                         placeholder="https://example.com/..." className={`mt-1 font-mono ${inputClass}`} />
                </label>
              </div>
              <div className="flex flex-col gap-4">
                <label className="flex-1 flex flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed border-slate-700 hover:border-sky-600 p-4 cursor-pointer text-center">
                  {preview
                    ? <img src={preview} alt="Selected post" className="max-h-48 rounded object-contain" />
                    : <><ImagePlus className="w-8 h-8 text-slate-500" /><span className="text-sm text-slate-400">Upload post image</span></>}
                  <span className="text-[11px] text-slate-500 break-all">{image ? image.name : 'JPEG, PNG, WebP'}</span>
                  <input type="file" accept="image/*" className="hidden" onChange={(e) => setImage(e.target.files?.[0] || null)} />
                </label>
                {image && <button type="button" onClick={() => setImage(null)} className="text-xs text-slate-400 hover:text-slate-200">Remove image</button>}
                <button type="submit" disabled={!canSubmit}
                        className="flex items-center justify-center gap-2 rounded-lg bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 disabled:text-slate-400 px-4 py-3 text-sm font-bold tracking-wide">
                  {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />} ANALYZE POST
                </button>
              </div>
            </form>

            {error && <p className="rounded-lg border border-red-800 bg-red-950/50 p-4 text-sm text-red-300">{error}</p>}
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
    </main>
  )
}
