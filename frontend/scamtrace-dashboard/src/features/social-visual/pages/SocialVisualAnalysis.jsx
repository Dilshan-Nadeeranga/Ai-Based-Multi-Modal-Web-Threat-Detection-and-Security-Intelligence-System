import { useEffect, useMemo, useRef, useState } from 'react'
import { BarChart3, Database, DownloadCloud, ExternalLink, Eye, ImageOff, Link2, Loader2, Search } from 'lucide-react'
import AppShell from '../../../components/AppShell.jsx'
import { analyzePostStream, dataUrlToFile, fetchSocialPost } from '../api/socialVisualApi.js'
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
const RESULT_SECTIONS = [
  ['summary', 'Summary'], ['category', 'Category'], ['input', 'Input'], ['ocr', 'OCR'], ['text', 'Text'],
  ['brand', 'Brand'], ['logos', 'Logos'], ['destination', 'Destination'], ['visual', 'Visual'],
  ['consistency', 'Consistency'], ['risk', 'Risk'], ['evidence', 'Evidence'],
]

const inputClass = 'st-autofill w-full rounded-lg bg-st-low/60 px-3 py-2.5 text-sm text-st-navy outline-none ring-1 ring-st-container transition placeholder:text-st-outline focus:bg-white focus:ring-2 focus:ring-st-blue-dark'
const labelClass = 'text-xs font-bold uppercase tracking-wider text-st-muted'
const cardClass = 'rounded-xl bg-white p-6 shadow-sm ring-1 ring-st-container/60'
const primaryButton = 'flex items-center justify-center gap-2 rounded-lg bg-st-navy px-5 py-2.5 text-sm font-semibold text-white shadow-md shadow-st-navy/20 transition duration-200 hover:-translate-y-0.5 hover:bg-st-blue-dark hover:shadow-lg active:translate-y-0 disabled:cursor-not-allowed disabled:opacity-50 disabled:hover:translate-y-0'

function ResultNav() {
  const [active, setActive] = useState('summary')

  useEffect(() => {
    const observer = new IntersectionObserver((entries) => {
      const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)
      if (visible[0]) setActive(visible[0].target.id.replace('result-', ''))
    }, { rootMargin: '-150px 0px -55% 0px' })
    RESULT_SECTIONS.forEach(([id]) => {
      const element = document.getElementById(`result-${id}`)
      if (element) observer.observe(element)
    })
    return () => observer.disconnect()
  }, [])

  return (
    <nav className="st-fade-in st-no-scrollbar sticky top-[78px] z-30 -mx-1 overflow-x-auto rounded-xl bg-white/90 p-1.5 shadow-sm ring-1 ring-st-container/60 backdrop-blur"
         aria-label="Result sections">
      <ul className="flex gap-1 2xl:gap-1.5">
        {RESULT_SECTIONS.map(([id, label]) => (
          <li key={id} className="2xl:flex-1">
            <a href={`#result-${id}`}
               onClick={(event) => {
                 event.preventDefault()
                 document.getElementById(`result-${id}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
               }}
               className={`block whitespace-nowrap rounded-md px-3 py-1.5 text-center text-xs font-semibold transition-colors lg:px-2.5 lg:py-2 lg:text-[13px] 2xl:px-4 2xl:text-[15px] ${active === id
                 ? 'bg-st-navy-2 text-white' : 'text-st-muted hover:bg-st-container hover:text-st-navy'}`}>
              {label}
            </a>
          </li>
        ))}
      </ul>
    </nav>
  )
}

function Anchor({ id, children }) {
  return <div id={`result-${id}`} className="scroll-mt-36">{children}</div>
}

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
  const [liveSteps, setLiveSteps] = useState([])

  const resultsRef = useRef(null)

  const preview = useMemo(() => (image ? URL.createObjectURL(image) : null), [image])
  useEffect(() => () => preview && URL.revokeObjectURL(preview), [preview])
  useEffect(() => {
    if (result) resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }, [result])

  async function runAnalysis(input) {
    setResult(null)
    setLiveSteps([])
    setLoading(true)
    try {
      setResult(await analyzePostStream(input, (step) => setLiveSteps((steps) => [...steps.filter((s) => s.key !== step.key), step])))
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
    try {
      const post = await fetchSocialPost(postUrl.trim())
      const file = post.image ? await dataUrlToFile(post.image.data_url, post.image.filename) : null
      setPlatform(post.platform)
      setPostText(post.post_text || '')
      setEmbeddedUrl(post.embedded_url || '')
      setImage(file)
      setFetched(post)
    } catch (err) {
      setError(err.message)
    } finally {
      setFetching(false)
    }
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

        {tab === 'dataset' && <div key="dataset" className="st-fade-in"><DatasetTab /></div>}
        {tab === 'models' && <div key="models" className="st-fade-in"><ModelResultsTab /></div>}

        {tab === 'analyze' && (
          <div key="analyze" className="st-fade-in flex flex-col gap-6">
            <form onSubmit={handleFetch} className={`st-fade-up ${cardClass} space-y-3`}>
              <div className="flex items-start gap-3">
                <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-st-low text-st-blue-dark">
                  <Link2 className="h-5 w-5" aria-hidden="true" />
                </span>
                <div>
                  <h2 className="font-manrope text-lg font-semibold text-st-navy">Fetch a Social Post</h2>
                  <p className="text-xs text-st-muted">Paste a public Reddit or Facebook post URL to extract its details for preview.</p>
                </div>
              </div>
              <label className="block">
                <span className={labelClass}>Social post URL (Reddit or Facebook)</span>
                <div className="mt-1 flex flex-col sm:flex-row gap-3">
                  <input type="text" value={postUrl} onChange={(e) => setPostUrl(e.target.value)}
                         placeholder="https://www.reddit.com/r/Scams/comments/... or https://www.facebook.com/<page>/posts/..."
                         className={`flex-1 font-mono ${inputClass}`} />
                  <button type="submit" disabled={busy || !postUrl.trim()} className={primaryButton}>
                    {fetching ? <Loader2 className="w-4 h-4 animate-spin" /> : <DownloadCloud className="w-4 h-4" />} Fetch
                  </button>
                </div>
              </label>
              <p className="text-[11px] text-st-muted">
                {fetching ? 'Opening the post and extracting its text, embedded URL and image…'
                  : 'Extracts the post text, embedded URL and image for preview. Facebook works only for public posts visible without login.'}
              </p>
            </form>

            {fetching && (
              <div className={`st-fade-in ${cardClass} space-y-4`} aria-hidden="true">
                <div className="flex items-center gap-3">
                  <div className="st-shimmer h-10 w-10 rounded-lg" />
                  <div className="space-y-2"><div className="st-shimmer h-4 w-48 rounded" /><div className="st-shimmer h-3 w-72 rounded" /></div>
                </div>
                <div className="grid md:grid-cols-[1fr_280px] gap-6">
                  <div className="space-y-3">
                    <div className="st-shimmer h-10 rounded-lg" />
                    <div className="st-shimmer h-28 rounded-lg" />
                    <div className="st-shimmer h-10 rounded-lg" />
                  </div>
                  <div className="st-shimmer h-56 rounded-lg" />
                </div>
              </div>
            )}

            {fetched && (
            <form onSubmit={handleSubmit} className={`st-fade-up ${cardClass} space-y-5`}>
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="flex items-start gap-3">
                  <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-st-low text-st-blue-dark">
                    <Eye className="h-5 w-5" aria-hidden="true" />
                  </span>
                  <div>
                    <h2 className="font-manrope text-lg font-semibold text-st-navy">Preview Post Details</h2>
                    <p className="text-xs text-st-muted">
                      <span className="font-semibold text-st-navy">{fetched.source_name}</span> · {fetched.post_type} post.
                      Check or edit the extracted details, then analyze.
                    </p>
                  </div>
                </div>
                <a href={fetched.permalink} target="_blank" rel="noreferrer"
                   className="flex items-center gap-1 text-xs font-semibold text-st-blue-dark hover:underline">
                  Open original post <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
                </a>
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
                           placeholder="No embedded URL in this post" className={`mt-1 font-mono ${inputClass}`} />
                  </label>
                  {fetched.embedded_urls.length > 1 && (
                    <div>
                      <span className={labelClass}>Other URLs in the post</span>
                      <div className="mt-1 flex flex-wrap gap-2">
                        {fetched.embedded_urls.map((url) => (
                          <button key={url} type="button" onClick={() => setEmbeddedUrl(url)}
                                  className={`max-w-full truncate rounded-full px-3 py-1 font-mono text-[11px] ring-1 transition ${url === embeddedUrl
                                    ? 'bg-st-navy-2 text-white ring-st-navy-2' : 'bg-st-low text-st-ink ring-st-container hover:bg-st-container'}`}>
                            {url}
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
                <div className="flex flex-col gap-4">
                  <div>
                    <span className={labelClass}>Post image</span>
                    <div className="mt-1 flex min-h-48 flex-col items-center justify-center gap-2 rounded-lg bg-st-low/60 p-4 text-center ring-1 ring-st-container">
                      {preview
                        ? <img src={preview} alt="Fetched post" className="st-pop max-h-56 rounded object-contain shadow-sm transition-transform duration-300 hover:scale-[1.02]" />
                        : <><ImageOff className="w-8 h-8 text-st-muted" /><span className="text-sm text-st-muted">No image in this post</span></>}
                      {image && <span className="text-[11px] text-st-muted break-all">{image.name}</span>}
                    </div>
                  </div>
                  {image && <button type="button" onClick={() => setImage(null)} className="text-xs font-semibold text-st-muted hover:text-st-error">Remove image</button>}
                  <button type="submit" disabled={!canSubmit} className={`${primaryButton} py-3`}>
                    {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />} Analyze Post
                  </button>
                </div>
              </div>
            </form>
            )}

            {error && <p role="alert" className="st-fade-up rounded-lg bg-st-error-bg p-4 text-sm text-st-error-ink">{error}</p>}
            {(loading || result) && <AnalysisProgress running={loading} pipeline={result?.pipeline || liveSteps} />}

            {result && (
              <div ref={resultsRef} className="scroll-mt-24 space-y-6">
                <ResultNav />
                <div className="st-stagger space-y-6">
                  <Anchor id="summary"><ThreatAssessment assessment={result.assessment} disclaimer={result.disclaimer} /></Anchor>
                  <Anchor id="category"><ThreatCategoryCard classification={result.classification} /></Anchor>
                  <Anchor id="input"><InputEvidence input={result.input} postImage={result.post_image} /></Anchor>
                  <Anchor id="ocr">
                    <div className="grid lg:grid-cols-2 gap-6">
                      <OCRAnalysisCard ocr={result.ocr} preprocessing={result.preprocessing} />
                      <DuplicateEvidence preprocessing={result.preprocessing} />
                    </div>
                  </Anchor>
                  <Anchor id="text"><TextThreatCard textThreat={result.text_threat} /></Anchor>
                  <Anchor id="brand">
                    <BrandAnalysisCard brandAnalysis={result.brand_analysis} postImage={result.post_image} logoDetection={result.logo_detection} />
                  </Anchor>
                  <Anchor id="logos"><LogoDetectionCard logoDetection={result.logo_detection} /></Anchor>
                  <Anchor id="destination"><DestinationEvidence destination={result.destination} step={captureStep} /></Anchor>
                  <Anchor id="visual">
                    <VisualComparison postImage={result.post_image} screenshot={result.destination?.screenshot} visual={result.visual_similarity} />
                  </Anchor>
                  <Anchor id="consistency"><ConsistencyAnalysis consistency={result.consistency} /></Anchor>
                  <Anchor id="risk"><RiskBreakdown risk={result.risk} /></Anchor>
                  <Anchor id="evidence"><EvidenceSummary assessment={result.assessment} /></Anchor>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </AppShell>
  )
}
