import { Link, Navigate, useLocation } from 'react-router-dom'
import { ShieldOff } from 'lucide-react'
import { useAuth } from '../hooks/useAuth.js'
import AuthLoading from './AuthLoading.jsx'

/** UX guard only — /api/admin/* is protected by requireAuth + requireRole("ADMIN") on the gateway. */
export default function AdminRoute({ children }) {
  const { isAuthenticated, isAdmin, loading } = useAuth()
  const location = useLocation()

  if (loading) return <AuthLoading />
  if (!isAuthenticated) return <Navigate to="/login" replace state={{ from: location }} />
  if (!isAdmin) {
    return (
      <main className="flex-1 flex items-center justify-center px-4 py-16 bg-slate-950 text-slate-100">
        <div className="max-w-md w-full bg-slate-900/80 border border-slate-800 rounded-xl p-8 text-center space-y-4">
          <ShieldOff className="w-10 h-10 mx-auto text-red-400" />
          <h1 className="text-xl font-semibold">Access denied</h1>
          <p className="text-sm text-slate-400">This area is only available to administrators.</p>
          <Link to="/dashboard" className="inline-block text-sm text-sky-400 hover:text-sky-300">
            Back to dashboard
          </Link>
        </div>
      </main>
    )
  }
  return children
}
