import { createContext } from 'react'

/** { demo, reason, setDemo(on), backend: {state, detail, ready}, recheck() } — see DemoModeProvider. */
export const DemoModeContext = createContext(null)
