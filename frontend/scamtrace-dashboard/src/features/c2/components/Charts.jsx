// Plain-SVG charts (the dashboard has no chart library). Every chart has a text alternative.

/** Scans-per-bucket sparkline: total (cyan area) + flagged (red line). */
export function Sparkline({ series, height = 64, label = 'Scans over time' }) {
  if (!series?.length) return <p className="text-sm text-slate-400">No scans in this window.</p>
  const width = 320
  const max = Math.max(1, ...series.map((point) => point.total))
  const x = (index) => (series.length === 1 ? width / 2 : (index / (series.length - 1)) * width)
  const y = (value) => height - 4 - (value / max) * (height - 10)
  const line = (key) => series.map((point, index) => `${index ? 'L' : 'M'}${x(index).toFixed(1)},${y(point[key]).toFixed(1)}`).join(' ')
  const area = `${line('total')} L${width},${height} L0,${height} Z`
  const total = series.reduce((sum, point) => sum + point.total, 0)
  const flagged = series.reduce((sum, point) => sum + point.flagged, 0)
  return (
    <figure>
      <svg viewBox={`0 0 ${width} ${height}`} className="h-16 w-full" preserveAspectRatio="none" role="img" aria-label={`${label}: ${total} scans, ${flagged} flagged, peak ${max} per bucket`}>
        <path d={area} fill="rgba(34,211,238,0.14)" />
        <path d={line('total')} fill="none" stroke="#22d3ee" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
        <path d={line('flagged')} fill="none" stroke="#f87171" strokeWidth="1.5" vectorEffect="non-scaling-stroke" />
      </svg>
      <figcaption className="mt-1 flex justify-between font-mono text-[0.6875rem] text-slate-400">
        <span><span className="text-cyan-300">━</span> all scans · <span className="text-red-300">━</span> flagged</span>
        <span>peak {max}</span>
      </figcaption>
    </figure>
  )
}

/** Horizontal count bars (by class / source / language ...). */
export function CountBars({ counts, labels = {}, tone = 'bg-cyan-400/80', tones = {} }) {
  const entries = Object.entries(counts || {}).filter(([, value]) => value > 0).sort((a, b) => b[1] - a[1])
  if (!entries.length) return <p className="text-sm text-slate-400">No data.</p>
  const max = Math.max(...entries.map(([, value]) => value))
  return (
    <ul className="flex flex-col gap-1.5">
      {entries.map(([key, value]) => (
        <li key={key} className="grid grid-cols-[7.5rem_1fr_2.5rem] items-center gap-2 text-sm">
          <span className="truncate text-slate-300">{labels[key] || key}</span>
          <span className="h-2 overflow-hidden rounded-full bg-slate-800" aria-hidden="true">
            <span className={`block h-full rounded-full ${tones[key] || tone}`} style={{ width: `${(value / max) * 100}%` }} />
          </span>
          <span className="text-right font-mono text-xs text-slate-100">{value}</span>
        </li>
      ))}
    </ul>
  )
}

/**
 * Test macro-F1 per ablation row with 95 % bootstrap CI whiskers. rows: [{label, value, low, high, group, final}]
 */
export function CiBarChart({ rows, title = 'Test macro-F1 with 95 % CI' }) {
  const width = 760
  const rowHeight = 30
  const left = 230
  const right = 70
  const top = 24
  const height = top + rows.length * rowHeight + 28
  const scale = (value) => left + value * (width - left - right)
  const ticks = [0, 0.2, 0.4, 0.6, 0.8, 1]
  const groupTone = { single: '#38bdf8', pair: '#a78bfa', tri: '#34d399' }
  return (
    <figure>
      <svg viewBox={`0 0 ${width} ${height}`} className="w-full" role="img" aria-labelledby="c2-ci-title c2-ci-desc">
        <title id="c2-ci-title">{title}</title>
        <desc id="c2-ci-desc">
          {rows.map((row) => `${row.label}: ${row.value.toFixed(3)} (95% CI ${row.low.toFixed(3)} to ${row.high.toFixed(3)})`).join('; ')}
        </desc>
        {ticks.map((tick) => (
          <g key={tick}>
            <line x1={scale(tick)} x2={scale(tick)} y1={top - 6} y2={height - 24} stroke="#1e293b" />
            <text x={scale(tick)} y={height - 8} textAnchor="middle" fontSize="11" fill="#94a3b8" fontFamily="ui-monospace, monospace">
              {tick.toFixed(1)}
            </text>
          </g>
        ))}
        {rows.map((row, index) => {
          const y = top + index * rowHeight
          const color = groupTone[row.group] || '#38bdf8'
          return (
            <g key={row.label}>
              <text x={left - 10} y={y + 15} textAnchor="end" fontSize="12" fill={row.final ? '#f8fafc' : '#cbd5e1'} fontWeight={row.final ? 700 : 400}>
                {row.final ? '★ ' : ''}
                {row.label}
              </text>
              <rect x={left} y={y + 5} width={Math.max(0, scale(row.value) - left)} height={rowHeight - 12} rx="3" fill={color} opacity={row.final ? 0.95 : 0.6} />
              <line x1={scale(row.low)} x2={scale(row.high)} y1={y + 14} y2={y + 14} stroke="#f8fafc" strokeWidth="1.5" />
              <line x1={scale(row.low)} x2={scale(row.low)} y1={y + 8} y2={y + 20} stroke="#f8fafc" strokeWidth="1.5" />
              <line x1={scale(row.high)} x2={scale(row.high)} y1={y + 8} y2={y + 20} stroke="#f8fafc" strokeWidth="1.5" />
              <text x={width - right + 8} y={y + 18} fontSize="12" fill="#e2e8f0" fontFamily="ui-monospace, monospace">
                {row.value.toFixed(3)}
              </text>
            </g>
          )
        })}
      </svg>
      <figcaption className="mt-1 flex flex-wrap gap-4 font-mono text-[0.6875rem] text-slate-400">
        <span><span style={{ color: groupTone.single }}>■</span> single arm</span>
        <span><span style={{ color: groupTone.pair }}>■</span> pair</span>
        <span><span style={{ color: groupTone.tri }}>■</span> tri-modal</span>
        <span>whisker = 95 % bootstrap CI (1,000 resamples of the 68 test pages)</span>
      </figcaption>
    </figure>
  )
}

export function StatTile({ label, value, sub, tone = 'text-slate-50' }) {
  return (
    <div className="c2-panel rounded-xl border border-slate-800 px-4 py-3">
      <p className="font-mono text-[0.6875rem] uppercase tracking-wider text-slate-400">{label}</p>
      <p className={`mt-1 font-mono text-2xl font-semibold ${tone}`}>{value}</p>
      {sub && <p className="text-xs text-slate-400">{sub}</p>}
    </div>
  )
}

