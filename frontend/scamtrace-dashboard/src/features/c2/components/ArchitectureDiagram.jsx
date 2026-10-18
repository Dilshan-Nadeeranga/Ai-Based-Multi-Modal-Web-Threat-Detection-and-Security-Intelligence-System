/** "How C2 works": the tri-modal pipeline as an SVG (text inside is static, not scan data). */
export default function ArchitectureDiagram() {
  const box = (x, y, w, h, title, lines, tone) => (
    <g>
      <rect x={x} y={y} width={w} height={h} rx="8" fill="#0f172a" stroke={tone} strokeWidth="1.5" />
      <text x={x + w / 2} y={y + 20} textAnchor="middle" fontSize="13" fontWeight="700" fill="#f8fafc">
        {title}
      </text>
      {lines.map((line, index) => (
        <text key={line} x={x + w / 2} y={y + 38 + index * 15} textAnchor="middle" fontSize="11" fill="#94a3b8">
          {line}
        </text>
      ))}
    </g>
  )
  const arrow = (x1, y1, x2, y2) => (
    <line x1={x1} y1={y1} x2={x2} y2={y2} stroke="#475569" strokeWidth="1.5" markerEnd="url(#c2-arrow)" />
  )
  return (
    <figure>
      <svg viewBox="0 0 900 330" className="w-full" role="img" aria-labelledby="c2-arch-title c2-arch-desc">
        <title id="c2-arch-title">How C2 works</title>
        <desc id="c2-arch-desc">
          A URL is fetched safely or HTML is pasted. Part 2 parses it once. Three modalities run on the parsed page: DOM structure
          (Parts 3 and 4), multilingual content with TF-IDF and XLM-R text models (Parts 5 and 6), and static JavaScript behavior
          (Parts 7 and 8). Four model arms are combined by weighted late fusion into a risk score and a verdict with tiers and an
          evidence floor.
        </desc>
        <defs>
          <marker id="c2-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M0,0 L10,5 L0,10 z" fill="#475569" />
          </marker>
        </defs>
        {box(10, 125, 140, 80, 'Input', ['URL → safe static fetch', 'or pasted HTML', 'no JS, SSRF guard'], '#22d3ee')}
        {box(185, 125, 140, 80, 'Preprocess', ['Part 2: parse once', 'text, forms, links,', 'scripts as text'], '#22d3ee')}
        {box(370, 20, 200, 80, 'DOM structure', ['Parts 3–4: 52 features', '→ Random Forest arm'], '#38bdf8')}
        {box(370, 125, 200, 80, 'Content & language', ['Parts 5–6: en / si / ta text', '→ TF-IDF arm + XLM-R arm'], '#a78bfa')}
        {box(370, 230, 200, 80, 'JS behavior', ['Parts 7–8: AST, taint flows', '→ Behavior arm'], '#f472b6')}
        {box(615, 125, 130, 80, 'Fusion', ['Part 9A: weighted', 'late fusion', '(4 arms)'], '#34d399')}
        {box(775, 110, 115, 110, 'Verdict', ['risk 0–100', 'Legitimate', 'Suspicious', 'Malicious', '+ evidence floor'], '#fbbf24')}
        {arrow(150, 165, 183, 165)}
        {arrow(325, 165, 368, 60)}
        {arrow(325, 165, 368, 165)}
        {arrow(325, 165, 368, 270)}
        {arrow(570, 60, 613, 160)}
        {arrow(570, 165, 613, 165)}
        {arrow(570, 270, 613, 172)}
        {arrow(745, 165, 773, 165)}
      </svg>
      <figcaption className="mt-2 text-xs text-slate-400">
        One parsed page feeds three modalities; a failing modality never fails the request: its arm is dropped, the weights
        are renormalized, the thresholds calibrated for that arm subset are used and the result is marked “degraded”.
      </figcaption>
    </figure>
  )
}
