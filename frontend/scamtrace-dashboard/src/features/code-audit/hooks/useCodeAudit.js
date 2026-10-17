import { useCallback, useRef, useState } from 'react'
import {
  analyzeRepository,
  getFinding,
  getFindings,
  getScanRecord,
} from '../api/codeAuditApi.js'

/** Minimal summary from the gateway record when C4 cannot return the stored one. */
function resultFromRecord(record) {
  const path = record.repository_url.replace(/^https?:\/\/github\.com\//, '').split('/')
  return {
    scan_id: record.scan_id,
    status: record.status,
    repository: {
      owner: path[0] || '—',
      name: path[1] || record.repository_url,
      url: record.repository_url,
      default_branch: '—',
      total_files: '—',
      source_files: '—',
      languages: [],
    },
  }
}

/**
 * Hook managing the C4 flow: repository analysis, reopening a saved scan,
 * security findings, severity filtering and finding details.
 */
export function useCodeAudit() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState(null)

  const [scanLoading, setScanLoading] = useState(false)
  const [scanError, setScanError] = useState('')

  const [findings, setFindings] = useState(null)
  const [findingsLoading, setFindingsLoading] = useState(false)
  const [findingsError, setFindingsError] = useState('')
  const [severityFilter, setSeverityFilter] = useState(null)

  const [selectedFinding, setSelectedFinding] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const detailRequest = useRef(0)

  const resetFindings = useCallback(() => {
    setFindings(null)
    setFindingsError('')
    setSeverityFilter(null)
    setSelectedFinding(null)
  }, [])

  const loadFindings = useCallback(async (scanId, severity = null) => {
    setFindingsLoading(true)
    setFindingsError('')
    setSelectedFinding(null)
    try {
      const data = await getFindings(scanId, severity)
      setFindings(data)
      setSeverityFilter(severity)
    } catch (err) {
      setFindingsError(err?.message || 'Unable to load security findings.')
    } finally {
      setFindingsLoading(false)
    }
  }, [])

  /** Runs a new analysis; resolves to the C4 result (or null on failure). */
  const analyze = useCallback(
    async (repositoryUrl) => {
      if (loading) return null
      setLoading(true)
      setError('')
      try {
        return await analyzeRepository(repositoryUrl)
      } catch (err) {
        setError(
          err?.message ||
            'Unable to analyze repository. Please verify that the repository is public and try again.'
        )
        return null
      } finally {
        setLoading(false)
      }
    },
    [loading]
  )

  /** Loads a saved scan the user owns (summary + findings). */
  const openScan = useCallback(async (scanId) => {
    setScanLoading(true)
    setScanError('')
    setResult(null)
    resetFindings()
    try {
      const data = await getScanRecord(scanId)
      setResult(data.summary || resultFromRecord(data.scan))
      if (data.findings) {
        setFindings(data.findings)
      } else {
        setFindingsError('Findings are unavailable because the C4 service could not be reached.')
      }
    } catch (err) {
      setScanError(err.status === 404 ? 'This scan was not found in your projects.' : err.message)
    } finally {
      setScanLoading(false)
    }
  }, [resetFindings])

  const filterBySeverity = useCallback(
    (severity) => {
      if (!result?.scan_id || findingsLoading) return
      loadFindings(result.scan_id, severity)
    },
    [result, findingsLoading, loadFindings]
  )

  const selectFinding = useCallback(async (findingId) => {
    const request = ++detailRequest.current
    setDetailLoading(true)
    const detail = await getFinding(findingId).catch(() => null)
    if (request !== detailRequest.current) return
    setSelectedFinding(detail)
    setDetailLoading(false)
  }, [])

  const clearSelectedFinding = useCallback(() => {
    detailRequest.current += 1
    setSelectedFinding(null)
    setDetailLoading(false)
  }, [])

  return {
    loading,
    error,
    result,
    analyze,
    openScan,
    scanLoading,
    scanError,
    findings,
    findingsLoading,
    findingsError,
    severityFilter,
    filterBySeverity,
    selectedFinding,
    detailLoading,
    selectFinding,
    clearSelectedFinding,
  }
}
