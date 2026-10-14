import axios from 'axios'

// The session lives in an HttpOnly cookie set by the API Gateway; the browser sends it
// automatically with withCredentials. No token is ever read or stored by JavaScript.
const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:5000/api',
  withCredentials: true,
  headers: { 'Content-Type': 'application/json' },
})

/** User-facing message for an Axios error (gateway errors are `{ message, errors? }`). */
export function getErrorMessage(error, fallback = 'Something went wrong. Please try again.') {
  if (!error?.response) return 'Cannot reach the ScamTrace API Gateway. Please make sure it is running.'
  const data = error.response.data
  return (typeof data?.message === 'string' && data.message) ||
    (typeof data?.detail === 'string' && data.detail) ||
    fallback
}

export default api
