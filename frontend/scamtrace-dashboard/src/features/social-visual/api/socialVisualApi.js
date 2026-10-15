// API client for the C3 Social Media & Web Visual Threat Analyzer service.

const C3_BASE_URL = import.meta.env.VITE_C3_URL || 'http://localhost:8003'

export class SocialVisualApiError extends Error {
  constructor(message, status, code = null) {
    super(message)
    this.status = status
    this.code = code
  }
}

async function request(path, options = {}) {
  let response
  try {
    response = await fetch(`${C3_BASE_URL}${path}`, options)
  } catch {
    throw new SocialVisualApiError(
      `Cannot reach the C3 service at ${C3_BASE_URL}. Start it with "uvicorn app.main:app --port 8003".`,
      0,
    )
  }
  const data = await response.json().catch(() => null)
  if (!response.ok) {
    throw new SocialVisualApiError(data?.error?.message || `Request failed (HTTP ${response.status})`, response.status, data?.error?.code)
  }
  return data
}

/**
 * POST C3 /api/v1/social/analyze (multipart). Nothing is stored in the research dataset.
 * @param {{platform: string, postText: string, image: File|null, embeddedUrl: string}} input
 */
export function analyzePost({ platform, postText, image, embeddedUrl }) {
  const form = new FormData()
  form.append('platform', platform)
  form.append('post_text', postText || '')
  form.append('embedded_url', embeddedUrl || '')
  if (image) form.append('image', image)
  return request('/api/v1/social/analyze', { method: 'POST', body: form })
}

/** POST C3 /api/v1/social/fetch-post — post text, embedded URL and image of a public Reddit or Facebook post. */
export function fetchSocialPost(url) {
  return request('/api/v1/social/fetch-post', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  })
}

export async function dataUrlToFile(dataUrl, filename) {
  const blob = await (await fetch(dataUrl)).blob()
  return new File([blob], filename, { type: blob.type })
}

export const getDatasetStatistics = () => request('/api/v1/dataset/statistics')
export const getModelResults = () => request('/api/v1/social/model-results')
export const getPlatforms = () => request('/api/v1/social/platforms')
