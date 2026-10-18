import { useCallback, useEffect, useState } from 'react'
import { listProjects } from '../api/codeAuditApi.js'

const CHANGED_EVENT = 'scamtrace:projects-changed'

export function formatScanDate(value) {
  return new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

/** Tell every mounted project list (sidebar, project grid) to reload. */
export function notifyProjectsChanged() {
  window.dispatchEvent(new Event(CHANGED_EVENT))
}

/** The signed-in user's saved repositories (grouped scans), newest activity first. */
export function useProjects({ enabled = true } = {}) {
  const [projects, setProjects] = useState(null)
  const [error, setError] = useState('')

  const reload = useCallback(async () => {
    try {
      const data = await listProjects()
      setProjects(data.projects)
      setError('')
    } catch (err) {
      setError(err.message)
    }
  }, [])

  useEffect(() => {
    if (!enabled) return undefined
    let active = true
    listProjects()
      .then((data) => active && setProjects(data.projects))
      .catch((err) => active && setError(err.message))
    window.addEventListener(CHANGED_EVENT, reload)
    return () => {
      active = false
      window.removeEventListener(CHANGED_EVENT, reload)
    }
  }, [enabled, reload])

  return { projects, error, loading: enabled && projects === null && !error, reload }
}
