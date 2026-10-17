import { Route, Routes, useLocation } from 'react-router-dom'
import NavBar from './components/NavBar.jsx'
import Home from './features/home/pages/Home.jsx'

// Authentication (centralized in the API Gateway)
import AdminRoute from './features/auth/components/AdminRoute.jsx'
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

// C3 — Social Media & Web Visual Threat Analyzer
import SocialVisualAnalysis from './features/social-visual/pages/SocialVisualAnalysis.jsx'

// C4 — Code Quality & Vulnerability Auditor
import AuditProgress from './features/code-audit/pages/AuditProgress.jsx'
import PatchReview from './features/code-audit/pages/PatchReview.jsx'
import ProjectScan from './features/code-audit/pages/ProjectScan.jsx'
import RepositoryAudit from './features/code-audit/pages/RepositoryAudit.jsx'
import VulnerabilityReport from './features/code-audit/pages/VulnerabilityReport.jsx'

const protect = (element) => <ProtectedRoute>{element}</ProtectedRoute>
const STANDALONE_PAGES = new Set(['/', '/login', '/register', '/dashboard', '/profile', '/history', '/url-analyzer', '/social-visual-analysis'])

function App() {
  const { pathname } = useLocation()

  return (
    <>
      {/* These pages render their own light header or sidebar. */}
      {!STANDALONE_PAGES.has(pathname) && !pathname.startsWith('/code-audit') && <NavBar />}
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

        {/* C3 — Social Media & Web Visual Threat Analyzer */}
        <Route path="/social-visual-analysis" element={protect(<SocialVisualAnalysis />)} />

        {/* C4 — Code Quality & Vulnerability Auditor */}
        <Route path="/code-audit" element={protect(<RepositoryAudit />)} />
        <Route path="/code-audit/scans/:scanId" element={protect(<ProjectScan />)} />
        <Route path="/code-audit/progress" element={protect(<AuditProgress />)} />
        <Route path="/code-audit/report" element={protect(<VulnerabilityReport />)} />
        <Route path="/code-audit/patches" element={protect(<PatchReview />)} />
        <Route path="/code-audit/remediations/:remediationId/review" element={protect(<PatchReview />)} />
      </Routes>
    </>
  )
}

export default App
