import { useContext } from 'react'
import { DemoModeContext } from '../context/demoModeContext.js'

export function useDemoMode() {
  const value = useContext(DemoModeContext)
  if (!value) throw new Error('useDemoMode must be used inside <DemoModeProvider>')
  return value
}
