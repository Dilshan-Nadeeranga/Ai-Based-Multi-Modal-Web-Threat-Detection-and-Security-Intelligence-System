import { useCallback, useState } from 'react'

const STORAGE_KEY = 'c2.theme'

function readTheme() {
  try {
    return localStorage.getItem(STORAGE_KEY) === 'dark' ? 'dark' : 'light'
  } catch {
    return 'light'
  }
}

/** C2-only colour theme: 'light' (default, matches the dashboard) | 'dark' (security console). */
export function useC2Theme() {
  const [theme, setThemeState] = useState(readTheme)
  const setTheme = useCallback((value) => {
    setThemeState(value)
    try {
      localStorage.setItem(STORAGE_KEY, value)
    } catch {
      /* private window: the switch still works for this visit */
    }
  }, [])
  return [theme, setTheme]
}
