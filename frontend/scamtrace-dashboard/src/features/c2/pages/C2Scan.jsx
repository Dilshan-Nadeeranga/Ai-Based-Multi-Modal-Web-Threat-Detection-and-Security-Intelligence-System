import { useEffect, useRef, useState } from 'react'
import { Link2, Play, ScanLine, Square, Workflow } from 'lucide-react'
import { analyze } from '../api/c2Api.js'
import PipelineStages from '../components/PipelineStages.jsx'
import ResultView from '../components/ResultView.jsx'
import { Panel, SegmentedControl, StateBox } from '../components/ui.jsx'
import { DEMO_EXAMPLES, demoAnalyze } from '../demo/demoData.js'
import { useDemoMode } from '../hooks/useDemoMode.js'

const MAX_HTML_BYTES = 5 * 1024 * 1024

function normalizeUrl(text) {
  const value = text.trim()
  if (!value) return { error: 'Enter a URL to analyze.' }
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `https://${value}`
  try {
    const parsed = new URL(withScheme)
    if (!['http:', 'https:'].includes(parsed.protocol)) return { error: 'Only http:// and https:// URLs can be analyzed.' }
    if (withScheme.length > 2048) return { error: 'The URL is longer than 2,048 characters.' }
    return { url: withScheme }
  } catch {
    return { error: 'That does not look like a URL.' }
  }
}

export default function C2Scan() {
  const { demo } = useDemoMode()
  const [mode, setMode] = useState('url')
  const [urlText, setUrlText] = useState('')
  const [html, setHtml] = useState('')
  const [htmlUrl, setHtmlUrl] = useState('')
  const [run, setRun] = useState({ state: 'idle', result: null, error: null, startedAt: null, target: null })
  const [inputError, setInputError] = useState(null)
  const controller = useRef(null)
  const resultRef = useRef(null)

  useEffect(() => () => controller.current?.abort(), [])

  useEffect(() => {
    if (run.state === 'done') resultRef.current?.focus({ preventScroll: false })
  }, [run.state])

  async function start(event) {
    event?.preventDefault()
    setInputError(null)
    let body
    let target
    if (mode === 'url') {
      if (demo) {
        target = urlText.trim() || DEMO_EXAMPLES[1].input
        body = { url: target }
      } else {
        const checked = normalizeUrl(urlText)
        if (checked.error) return setInputError(checked.error)
        target = checked.url
        body = { url: checked.url }
      }
    } else {
      if (!html.trim()) return setInputError('Paste the page HTML first.')
      if (new Blob([html]).size > MAX_HTML_BYTES) return setInputError('The HTML is larger than 5 MB.')
      const checked = htmlUrl.trim() ? normalizeUrl(htmlUrl) : { url: undefined }
      if (checked.error) return setInputError(`Page URL: ${checked.error}`)
      target = checked.url || null
      body = { html, url: checked.url }
    }
    controller.current?.abort()
    controller.current = new AbortController()
    const { signal } = controller.current
    setRun({ state: 'running', result: null, error: null, startedAt: Date.now(), target })
    try {
      const result = demo ? await demoAnalyze(body.url || 'html', { signal }) : await analyze(body, { signal })
      setRun((previous) => ({ ...previous, state: 'done', result }))
    } catch (error) {
      if (error?.name === 'AbortError' || error?.kind === 'cancelled') {
        setRun((previous) => ({ ...previous, state: 'idle' }))
        return
      }
      setRun((previous) => ({ ...previous, state: 'error', error }))
    }
  }

  function cancel() {
    controller.current?.abort()
  }

  const running = run.state === 'running'
  return (
    <div className="flex flex-col gap-4">
      <Panel title="Scan a page" icon={ScanLine}>
        <form onSubmit={start} className="flex flex-col gap-3" noValidate>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <SegmentedControl
              label="Input type"
              value={mode}
              onChange={setMode}
              options={[
                { value: 'url', label: 'URL' },
                { value: 'html', label: 'Paste HTML' },
              ]}
            />
            <p className="text-xs text-[color:var(--c2-fg-muted)]">
              {mode === 'url'
                ? 'C2 fetches the page itself: one static GET, no JavaScript, private addresses refused.'
                : 'Nothing is fetched; the URL (optional) only resolves relative links.'}
            </p>
          </div>

          {mode === 'url' ? (
            <div className="flex flex-col gap-2 md:flex-row">
              <label htmlFor="c2-url" className="sr-only">
                URL to analyze
              </label>
              <div className="relative flex-1">
                <Link2 className="pointer-events-none absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-[color:var(--c2-accent-icon)]" aria-hidden="true" />
                <input
                  id="c2-url"
                  type="text"
                  inputMode="url"
                  autoComplete="off"
                  spellCheck="false"
                  value={urlText}
                  onChange={(event) => setUrlText(event.target.value)}
                  placeholder={demo ? 'Pick a demo example below, or type anything' : 'https://suspicious-site.example/login'}
                  aria-invalid={Boolean(inputError)}
                  aria-describedby={inputError ? 'c2-input-error' : undefined}
                  className="w-full rounded-lg border border-[color:var(--c2-border-strong)] bg-[color:var(--c2-field-deep)] py-3.5 pl-11 pr-3 font-mono text-base text-[color:var(--c2-fg-strong)] placeholder:text-[color:var(--c2-fg-faint)] focus:border-[color:var(--c2-accent-solid)]"
                />
              </div>
              <AnalyzeButton running={running} onCancel={cancel} />
            </div>
          ) : (
            <div className="flex flex-col gap-2">
              <label htmlFor="c2-html" className="text-sm font-medium text-[color:var(--c2-fg-2)]">
                Page HTML
              </label>
              <textarea
                id="c2-html"
                value={html}
                onChange={(event) => setHtml(event.target.value)}
                rows={8}
                spellCheck="false"
                placeholder="<html>…</html>"
                aria-invalid={Boolean(inputError)}
                className="w-full rounded-lg border border-[color:var(--c2-border-strong)] bg-[color:var(--c2-field-deep)] p-3 font-mono text-sm text-[color:var(--c2-fg-hi)] placeholder:text-[color:var(--c2-fg-faint)] focus:border-[color:var(--c2-accent-solid)]"
              />
              <div className="flex flex-col gap-2 md:flex-row md:items-end">
                <label htmlFor="c2-html-url" className="flex flex-1 flex-col gap-1 text-sm font-medium text-[color:var(--c2-fg-2)]">
                  Page URL (optional, never fetched)
                  <input
                    id="c2-html-url"
                    type="text"
                    value={htmlUrl}
                    onChange={(event) => setHtmlUrl(event.target.value)}
                    className="rounded-lg border border-[color:var(--c2-border-strong)] bg-[color:var(--c2-field-deep)] px-3 py-2 font-mono text-sm text-[color:var(--c2-fg-hi)] focus:border-[color:var(--c2-accent-solid)]"
                  />
                </label>
                <AnalyzeButton running={running} onCancel={cancel} />
              </div>
            </div>
          )}
          {inputError && (
            <p id="c2-input-error" role="alert" className="text-sm text-[color:var(--c2-sus)]">
              {inputError}
            </p>
          )}
          {demo && mode === 'url' && (
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs uppercase tracking-wider text-[color:var(--c2-sus-hi)]">Demo examples:</span>
              {DEMO_EXAMPLES.map((example) => (
                <button
                  key={example.key}
                  type="button"
                  onClick={() => setUrlText(example.input)}
                  className="rounded-md border border-[color:var(--c2-border-strong)] px-2.5 py-1 text-left text-xs text-[color:var(--c2-fg)] hover:border-[color:var(--c2-sus-line)] hover:text-[color:var(--c2-sus-ink)]"
                >
                  <span className="font-semibold">{example.label}</span>
                  <span className="text-[color:var(--c2-fg-muted)]"> · {example.hint}</span>
                </button>
              ))}
            </div>
          )}
        </form>
      </Panel>

      {run.state !== 'idle' && (
        <Panel title="Pipeline" icon={Workflow}>
          <p className="sr-only" role="status">
            {running ? 'Analyzing…' : run.state === 'done' ? 'Analysis complete.' : ''}
          </p>
          <PipelineStages running={running} startedAt={run.startedAt} result={run.result} target={run.target} />
        </Panel>
      )}

      {run.state === 'error' && (
        <StateBox state="error" message={run.error?.message} onRetry={() => start()}>
          {run.error?.kind === 'network' && (
            <p className="text-xs text-[color:var(--c2-fg-muted)]">Tip: switch on Demo mode (top right) to present with recorded results.</p>
          )}
        </StateBox>
      )}

      {run.state === 'idle' && (
        <StateBox state="empty" message="Enter a URL (or paste HTML) and press Analyze. The result shows the verdict, the risk score and why — with the evidence from every modality." />
      )}

      {run.state === 'done' && (
        <div ref={resultRef} tabIndex={-1} className="outline-none" aria-label="Analysis result">
          <ResultView result={run.result} />
        </div>
      )}
    </div>
  )
}

function AnalyzeButton({ running, onCancel }) {
  if (running) {
    return (
      <button
        type="button"
        onClick={onCancel}
        className="inline-flex items-center justify-center gap-2 rounded-lg border border-[color:var(--c2-border-stronger)] px-6 py-3.5 text-base font-semibold text-[color:var(--c2-fg-hi)] hover:border-[color:var(--c2-sus-line)]"
      >
        <Square className="h-4 w-4" aria-hidden="true" /> Cancel
      </button>
    )
  }
  return (
    <button
      type="submit"
      className="inline-flex items-center justify-center gap-2 rounded-lg bg-[color:var(--c2-accent-solid)] px-7 py-3.5 text-base font-semibold text-[color:var(--c2-on-accent)] c2-accent-glow hover:bg-[color:var(--c2-accent-solid-hover)]"
    >
      <Play className="h-4 w-4" aria-hidden="true" /> Analyze
    </button>
  )
}
