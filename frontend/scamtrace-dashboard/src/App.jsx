import { lazy, Suspense } from 'react'
import { Route, Routes, useLocation } from 'react-router-dom'
import NavBar from './components/NavBar.jsx'
import Home from './features/home/pages/Home.jsx'

// Authentication (centralized in the API Gateway)
import AdminRoute from './features/auth/components/AdminRoute.jsx'
import AuthLoading from './features/auth/components/AuthLoading.jsx'
import ProtectedRoute from './features/auth/components/ProtectedRoute.jsx'
import Login from './features/auth/pages/Login.jsx'
import Register from './features/auth/pages/Register.jsx'
import AdminDashboard from './features/admin/pages/AdminDashboard.jsx'
import UserManagement from './features/admin/pages/UserManagement.jsx'
import Dashboard from './features/dashboard/pages/Dashboard.jsx'
import History from './features/history/pages/History.jsx'
import Profile from './features/profile/pages/Profile.jsx'

// C1 — Intelligent URL & Domain Analyzer
import UrlAnalyzer from './features/url-analyzer/pages/UrlAnalyzer.jsx'

// C2 — HTML Content & Behavior Analyzer (loaded on demand: not in the main bundle)
const C2Layout = lazy(() => import('./features/c2/components/C2Layout.jsx'))
const C2Feed = lazy(() => import('./features/c2/pages/C2Feed.jsx'))
const C2History = lazy(() => import('./features/c2/pages/C2History.jsx'))
const C2Research = lazy(() => import('./features/c2/pages/C2Research.jsx'))
const C2Scan = lazy(() => import('./features/c2/pages/C2Scan.jsx'))
const C2ScanDetail = lazy(() => import('./features/c2/pages/C2ScanDetail.jsx'))

// C3 — Social Media & Web Visual Threat Analyzer
import SocialVisualAnalysis from './features/social-visual/pages/SocialVisualAnalysis.jsx'

// C4 — Code Quality & Vulnerability Auditor
import AuditProgress from './features/code-audit/pages/AuditProgress.jsx'
import PatchReview from './features/code-audit/pages/PatchReview.jsx'
import RepositoryAudit from './features/code-audit/pages/RepositoryAudit.jsx'
import VulnerabilityReport from './features/code-audit/pages/VulnerabilityReport.jsx'

const protect = (element) => <ProtectedRoute>{element}</ProtectedRoute>
const STANDALONE_PAGES = new Set(['/', '/login', '/register', '/dashboard', '/profile', '/history', '/url-analyzer', '/social-visual-analysis'])

function App() {
  const { pathname } = useLocation()

  return (
    <>
      {/* These pages render their own light header or sidebar. */}
      {!STANDALONE_PAGES.has(pathname) && !pathname.startsWith('/code-audit') && !pathname.startsWith('/c2') && <NavBar />}
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />

        <Route path="/dashboard" element={protect(<Dashboard />)} />
        <Route path="/history" element={protect(<History />)} />
        <Route path="/profile" element={protect(<Profile />)} />

        <Route path="/admin" element={<AdminRoute><AdminDashboard /></AdminRoute>} />
        <Route path="/admin/users" element={<AdminRoute><UserManagement /></AdminRoute>} />

        {/* C1 — Intelligent URL & Domain Analyzer */}
        <Route path="/url-analyzer" element={protect(<UrlAnalyzer />)} />

        {/* C2 — HTML Content & Behavior Analyzer (section layout + tabs) */}
        <Route path="/c2" element={protect(<Suspense fallback={<AuthLoading light />}><C2Layout /></Suspense>)}>
          <Route index element={<C2Scan />} />
          <Route path="feed" element={<C2Feed />} />
          <Route path="research" element={<C2Research />} />
          <Route path="history" element={<C2History />} />
          <Route path="scans/:scanId" element={<C2ScanDetail />} />
        </Route>

        {/* C3 — Social Media & Web Visual Threat Analyzer */}
        <Route path="/social-visual-analysis" element={protect(<SocialVisualAnalysis />)} />

        {/* C4 — Code Quality & Vulnerability Auditor */}
        <Route path="/code-audit" element={protect(<RepositoryAudit />)} />
        <Route path="/code-audit/progress" element={protect(<AuditProgress />)} />
        <Route path="/code-audit/report" element={protect(<VulnerabilityReport />)} />
        <Route path="/code-audit/patches" element={protect(<PatchReview />)} />
        <Route path="/code-audit/remediations/:remediationId/review" element={protect(<PatchReview />)} />
      </Routes>
    </>
  )
}

export default App
