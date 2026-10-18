import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { getReady } from '../api/c2Api.js'
import { DemoModeContext } from './demoModeContext.js'

const STORAGE_KEY = 'c2.demoMode'
const RECHECK_LOADING_MS = 3000

function readChoice() {
  try {
    return localStorage.getItem(STORAGE_KEY) // 'on' | 'off' | null (= automatic)
  } catch {
    return null
  }
}

function saveChoice(value) {
  try {
    localStorage.setItem(STORAGE_KEY, value)
  } catch {
    /* private window: the switch still works for this visit */
  }
}

/**
 * Demo mode for the presentation. ON when the presenter switches it on, or automatically when
 * C2's GET /ready cannot be reached / reports a broken model load. While the models are still
 * loading (/ready 503 + loading) it waits and checks again instead of switching.
 */
export default function DemoModeProvider({ children }) {
  const [choice, setChoice] = useState(readChoice)
  const [backend, setBackend] = useState({ state: 'checking', detail: null, ready: null })
  const timer = useRef(null)

  const recheck = useCallback(async function probe() {
    clearTimeout(timer.current)
    setBackend((previous) => ({ ...previous, state: 'checking' }))
    try {
      const ready = await getReady()
      if (ready.ready) setBackend({ state: 'online', detail: null, ready })
      else if (ready.loading) {
        setBackend({ state: 'loading', detail: ready.reason || 'models are loading', ready })
        timer.current = setTimeout(probe, RECHECK_LOADING_MS)
      } else setBackend({ state: 'degraded', detail: ready.reason || 'models not usable', ready })
    } catch (error) {
      setBackend({ state: 'offline', detail: error.message, ready: null })
    }
  }, [])

  useEffect(() => {
    recheck() // probe C2 /ready once on entry (state updates happen after the request)
    return () => clearTimeout(timer.current)
  }, [recheck])

  const autoDemo = backend.state === 'offline' || backend.state === 'degraded'
  const demo = choice === 'on' || (choice !== 'off' && autoDemo)
  const reason = choice === 'on' ? 'manual' : demo ? 'auto' : null

  const setDemo = useCallback(
    (on) => {
      const value = on ? 'on' : 'off'
      saveChoice(value)
      setChoice(value)
      if (!on) recheck()
    },
    [recheck],
  )

  const value = useMemo(() => ({ demo, reason, setDemo, backend, recheck }), [demo, reason, setDemo, backend, recheck])
  return <DemoModeContext.Provider value={value}>{children}</DemoModeContext.Provider>
}
