import { useEffect, useState } from 'react'

const reducedMotion = () => window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

/** Animates a number from 0 to `target` (ease-out) and returns the current value. */
export default function useCountUp(target, duration = 900) {
  const [value, setValue] = useState(0)

  useEffect(() => {
    const end = Number(target) || 0
    let frame
    const started = performance.now()
    const tick = (now) => {
      const t = reducedMotion() ? 1 : Math.min(1, (now - started) / duration)
      setValue(end * (1 - (1 - t) ** 3))
      if (t < 1) frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [target, duration])

  return value
}
