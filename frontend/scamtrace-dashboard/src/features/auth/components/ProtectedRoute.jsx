import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth.js'
import AuthLoading from './AuthLoading.jsx'

/** UX guard only — every protected API is enforced by the API Gateway. */
export default function ProtectedRoute({ children }) {
  const { isAuthenticated, loading } = useAuth()
  const location = useLocation()

  if (loading) return <AuthLoading />
  if (!isAuthenticated) return <Navigate to="/login" replace state={{ from: location }} />
  return children
}
