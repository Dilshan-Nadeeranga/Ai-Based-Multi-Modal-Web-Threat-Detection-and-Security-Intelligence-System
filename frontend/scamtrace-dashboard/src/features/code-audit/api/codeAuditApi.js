// API client for the C4 Code Quality & Vulnerability Auditor service.

const API_BASE_URL =
  import.meta.env.VITE_C4_API_BASE_URL || 'http://localhost:8000/api/v1'

export class CodeAuditApiError extends Error {
  constructor(message, status) {
    super(message)
    this.status = status
  }
}

/**
 * POST /repositories/analyze
 * @param {string} repositoryUrl public GitHub repository URL
 */
export async function analyzeRepository(repositoryUrl) {
  let response
  try {
    response = await fetch(`${API_BASE_URL}/repositories/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repository_url: repositoryUrl }),
    })
  } catch {
    throw new CodeAuditApiError(
      'Backend is unavailable. Please make sure the analysis service is running.',
      0
    )
  }

  let data = null
  try {
    data = await response.json()
  } catch {
    // non-JSON error body
  }

  if (!response.ok) {
    const detail = data && data.detail
    const messages = {
      400: 'Invalid GitHub URL. Use the form https://github.com/owner/repository.',
      404: 'Repository not found. It may not exist, or it is private (private repositories are not supported yet).',
      429: 'GitHub rate limit reached. Please try again in a few minutes.',
      502: 'Unable to analyze repository. Please verify that the repository is public and try again.',
    }
    throw new CodeAuditApiError(
      (typeof detail === 'string' && detail) ||
        messages[response.status] ||
        'Unknown server error. Please try again.',
      response.status
    )
  }

  return data
}

/** GET /health */
export async function getServiceHealth() {
  const response = await fetch(`${API_BASE_URL}/health`)
  if (!response.ok) throw new CodeAuditApiError('Health check failed', response.status)
  return response.json()
}

async function requestJson(url, fallbackMessage) {
  let response
  try {
    response = await fetch(url)
  } catch {
    throw new CodeAuditApiError(
      'Backend is unavailable. Please make sure the analysis service is running.',
      0
    )
  }
  let data = null
  try {
    data = await response.json()
  } catch {
    // non-JSON body
  }
  if (!response.ok) {
    const detail = data && data.detail
    throw new CodeAuditApiError(
      (typeof detail === 'string' && detail) || fallbackMessage,
      response.status
    )
  }
  return data
}

/**
 * GET /scans/{scanId}/findings[?severity=...]
 * @param {string} scanId
 * @param {string|null} severity CRITICAL | HIGH | MEDIUM | LOW | null for all
 */
export function getFindings(scanId, severity = null) {
  const query = severity ? `?severity=${encodeURIComponent(severity)}` : ''
  return requestJson(
    `${API_BASE_URL}/scans/${encodeURIComponent(scanId)}/findings${query}`,
    'Unable to load security findings.'
  )
}

/** GET /findings/{findingId} */
export function getFinding(findingId) {
  return requestJson(
    `${API_BASE_URL}/findings/${encodeURIComponent(findingId)}`,
    'Unable to load finding details.'
  )
}

/**
 * POST /findings/{findingId}/remediation
 * Generates an UNVALIDATED AI remediation suggestion (never applied automatically).
 */
export async function generateRemediation(findingId) {
  let response
  try {
    response = await fetch(
      `${API_BASE_URL}/findings/${encodeURIComponent(findingId)}/remediation`,
      { method: 'POST' }
    )
  } catch {
    throw new CodeAuditApiError(
      'Backend is unavailable. Please make sure the analysis service is running.',
      0
    )
  }
  let data = null
  try {
    data = await response.json()
  } catch {
    // non-JSON body
  }
  if (!response.ok) {
    const message = (data && (data.message || data.detail)) || 'Unable to generate a remediation suggestion.'
    throw new CodeAuditApiError(typeof message === 'string' ? message : 'Unable to generate a remediation suggestion.', response.status)
  }
  return data
}
