// API client for the C4 Code Quality & Vulnerability Auditor service.

const API_BASE_URL =
  import.meta.env.VITE_C4_API_BASE_URL || 'http://localhost:8000/api/v1'
// Repository submissions go through the authenticated API Gateway, which records scan ownership.
const GATEWAY_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api'

export class CodeAuditApiError extends Error {
  constructor(message, status, code = null, data = null) {
    super(message)
    this.status = status
    this.code = code
    this.data = data
  }
}

/**
 * POST {gateway}/code-audit → C4 POST /repositories/analyze (authenticated; the scan is owned by the user)
 * @param {string} repositoryUrl public GitHub repository URL
 */
export async function analyzeRepository(repositoryUrl) {
  let response
  try {
    response = await fetch(`${GATEWAY_BASE_URL}/code-audit`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repository_url: repositoryUrl }),
    })
  } catch {
    throw new CodeAuditApiError(
      'Backend is unavailable. Please make sure the API Gateway and analysis service are running.',
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
    const detail = data && (data.detail || data.message)
    const messages = {
      401: 'Your session has expired. Please log in again.',
      400: 'Invalid GitHub URL. Use the form https://github.com/owner/repository.',
      404: 'Repository not found. It may not exist, or it is private (private repositories are not supported yet).',
      422: 'Unsupported repository: at least 70% of the code must be JavaScript/TypeScript.',
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

async function gatewayRequest(path, fallbackMessage, method = 'GET') {
  let response
  try {
    response = await fetch(`${GATEWAY_BASE_URL}${path}`, { method, credentials: 'include' })
  } catch {
    throw new CodeAuditApiError('Backend is unavailable. Please make sure the API Gateway is running.', 0)
  }
  let data = null
  try {
    data = await response.json()
  } catch {
    // non-JSON body
  }
  if (!response.ok) {
    const message = data && (data.message || data.detail)
    throw new CodeAuditApiError(typeof message === 'string' ? message : fallbackMessage, response.status)
  }
  return data
}

/** GET {gateway}/code-audit/projects — the user's saved repositories with their scan history */
export function listProjects() {
  return gatewayRequest('/code-audit/projects', 'Unable to load your projects.')
}

/** DELETE {gateway}/code-audit/projects/{scanId} — removes the user's project containing this scan */
export function deleteProject(scanId) {
  return gatewayRequest(`/code-audit/projects/${encodeURIComponent(scanId)}`, 'Unable to delete this project.', 'DELETE')
}

/** GET {gateway}/code-audit/{scanId} — owned scan record + stored C4 summary and findings */
export function getScanRecord(scanId) {
  return gatewayRequest(`/code-audit/${encodeURIComponent(scanId)}`, 'Unable to load this scan.')
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
    const detail = data && (data.message || data.detail)
    throw new CodeAuditApiError(
      (typeof detail === 'string' && detail) || fallbackMessage,
      response.status,
      data?.error_code || null,
      data
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

async function postJson(url, fallbackMessage, body = undefined) {
  let response
  try {
    response = await fetch(url, {
      method: 'POST',
      ...(body !== undefined && {
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      }),
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
    // non-JSON body
  }
  if (!response.ok) {
    const message = data && (data.message || data.detail)
    throw new CodeAuditApiError(
      typeof message === 'string' ? message : fallbackMessage,
      response.status,
      data?.error_code || null,
      data
    )
  }
  return data
}

/**
 * POST /findings/{findingId}/remediation
 * Generates an UNVALIDATED AI remediation suggestion (never applied automatically).
 */
export function generateRemediation(findingId) {
  return postJson(
    `${API_BASE_URL}/findings/${encodeURIComponent(findingId)}/remediation`,
    'Unable to generate a remediation suggestion.'
  )
}

/** GET /findings/{findingId}/remediations (newest first) */
export function listRemediations(findingId) {
  return requestJson(
    `${API_BASE_URL}/findings/${encodeURIComponent(findingId)}/remediations`,
    'Unable to load remediation suggestions.'
  )
}

/**
 * POST /remediations/{remediationId}/validate
 * Runs deterministic static checks on the candidate patch (never applied or executed).
 */
export function validateRemediation(remediationId) {
  return postJson(
    `${API_BASE_URL}/remediations/${encodeURIComponent(remediationId)}/validate`,
    'Unable to validate the candidate patch.'
  )
}

/** GET /validations/{validationId} */
export function getValidation(validationId) {
  return requestJson(
    `${API_BASE_URL}/validations/${encodeURIComponent(validationId)}`,
    'Unable to load the validation result.'
  )
}

/** GET /remediations/{remediationId}/review — finding, remediation, validation, review, policy */
export function getReviewWorkspace(remediationId) {
  return requestJson(
    `${API_BASE_URL}/remediations/${encodeURIComponent(remediationId)}/review`,
    'Unable to load the analyst review.'
  )
}

/** POST /remediations/{remediationId}/review/start — idempotent review-session start */
export function startReview(remediationId) {
  return postJson(
    `${API_BASE_URL}/remediations/${encodeURIComponent(remediationId)}/review/start`,
    'Unable to start the review session.'
  )
}

/**
 * POST /remediations/{remediationId}/review
 * Records the human decision (ACCEPTED | REJECTED). ACCEPTED also applies the patch
 * to the project's stored repository copy (never to GitHub).
 */
export function submitReviewDecision(remediationId, decision, reason = null) {
  return postJson(
    `${API_BASE_URL}/remediations/${encodeURIComponent(remediationId)}/review`,
    'Decision could not be saved. No repository changes were made.',
    { decision, ...(reason ? { reason } : {}) }
  )
}

/** POST /remediations/{remediationId}/review/apply — retry applying an accepted patch */
export function applyAcceptedPatch(remediationId) {
  return postJson(
    `${API_BASE_URL}/remediations/${encodeURIComponent(remediationId)}/review/apply`,
    'The patch could not be applied.'
  )
}

/**
 * GET /scans/{scanId}/risk-score
 * Preliminary internal risk index (model v0.1) — not CVSS, not an exploit probability.
 */
export function getRiskScore(scanId) {
  return requestJson(
    `${API_BASE_URL}/scans/${encodeURIComponent(scanId)}/risk-score`,
    'Unable to calculate the preliminary risk score.'
  )
}

/** POST /scans/{scanId}/risk-score/recalculate — always stores a new assessment */
export function recalculateRiskScore(scanId) {
  return postJson(
    `${API_BASE_URL}/scans/${encodeURIComponent(scanId)}/risk-score/recalculate`,
    'Unable to recalculate the preliminary risk score.'
  )
}
