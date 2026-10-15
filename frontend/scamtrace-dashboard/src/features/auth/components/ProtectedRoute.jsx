import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth.js'
import AuthLoading from './AuthLoading.jsx'

const LIGHT_PAGES = new Set(['/dashboard', '/profile', '/history', '/url-analyzer', '/social-visual-analysis'])

/** UX guard only — every protected API is enforced by the API Gateway. */
export default function ProtectedRoute({ children }) {
  const { isAuthenticated, loading } = useAuth()
  const location = useLocation()

  if (loading) {
    const light = LIGHT_PAGES.has(location.pathname) || location.pathname.startsWith('/code-audit')
    return <AuthLoading light={light} />
  }
  if (!isAuthenticated) return <Navigate to="/login" replace state={{ from: location }} />
  return children
}
