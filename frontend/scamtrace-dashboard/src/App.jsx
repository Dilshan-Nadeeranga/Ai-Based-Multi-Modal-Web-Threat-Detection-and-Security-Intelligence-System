import { useState } from 'react'
import { Link, Route, Routes } from 'react-router-dom'
import heroImg from './assets/hero.png'
import reactLogo from './assets/react.svg'
import viteLogo from './assets/vite.svg'
import './App.css'
import NavBar from './components/NavBar.jsx'

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

// C4 — Code Quality & Vulnerability Auditor
import AuditProgress from './features/code-audit/pages/AuditProgress.jsx'
import PatchReview from './features/code-audit/pages/PatchReview.jsx'
import RepositoryAudit from './features/code-audit/pages/RepositoryAudit.jsx'
import VulnerabilityReport from './features/code-audit/pages/VulnerabilityReport.jsx'

const protect = (element) => <ProtectedRoute>{element}</ProtectedRoute>

function App() {
  return (
    <>
      <NavBar />
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

function Home() {
  const [count, setCount] = useState(0)

  return (
    <>
      <nav style={{ padding: '16px', background: '#0f172a', display: 'flex', gap: '16px', justifyContent: 'center' }}>
        <Link to="/url-analyzer" style={{ padding: '8px 16px', background: '#0284c7', color: '#fff', borderRadius: '6px', textDecoration: 'none', fontWeight: 600 }}>
          🛡️ Intelligent URL & Domain Analyzer (C1)
        </Link>
        <Link to="/code-audit" style={{ padding: '8px 16px', background: '#334155', color: '#fff', borderRadius: '6px', textDecoration: 'none', fontWeight: 600 }}>
          🔍 Code Audit (C4)
        </Link>
      </nav>
      <section id="center">
        <div className="hero">
          <img src={heroImg} className="base" width="170" height="179" alt="" />
          <img src={reactLogo} className="framework" alt="React logo" />
          <img src={viteLogo} className="vite" alt="Vite logo" />
        </div>
        <div>
          <h1>Get started</h1>
          <p>
            Edit <code>src/App.jsx</code> and save to test <code>HMR</code>
          </p>
        </div>
        <button
          type="button"
          className="counter"
          onClick={() => setCount((count) => count + 1)}
        >
          Count is {count}
        </button>
      </section>

      <div className="ticks"></div>

      <section id="next-steps">
        <div id="docs">
          <svg className="icon" role="presentation" aria-hidden="true">
            <use href="/icons.svg#documentation-icon"></use>
          </svg>
          <h2>Documentation</h2>
          <p>Your questions, answered</p>
          <ul>
            <li>
              <a href="https://vite.dev/" target="_blank">
                <img className="logo" src={viteLogo} alt="" />
                Explore Vite
              </a>
            </li>
            <li>
              <a href="https://react.dev/" target="_blank">
                <img className="button-icon" src={reactLogo} alt="" />
                Learn more
              </a>
            </li>
          </ul>
        </div>
        <div id="social">
          <svg className="icon" role="presentation" aria-hidden="true">
            <use href="/icons.svg#social-icon"></use>
          </svg>
          <h2>Connect with us</h2>
          <p>Join the Vite community</p>
          <ul>
            <li>
              <a href="https://github.com/vitejs/vite" target="_blank">
                <svg
                  className="button-icon"
                  role="presentation"
                  aria-hidden="true"
                >
                  <use href="/icons.svg#github-icon"></use>
                </svg>
                GitHub
              </a>
            </li>
            <li>
              <a href="https://chat.vite.dev/" target="_blank">
                <svg
                  className="button-icon"
                  role="presentation"
                  aria-hidden="true"
                >
                  <use href="/icons.svg#discord-icon"></use>
                </svg>
                Discord
              </a>
            </li>
            <li>
              <a href="https://x.com/vite_js" target="_blank">
                <svg
                  className="button-icon"
                  role="presentation"
                  aria-hidden="true"
                >
                  <use href="/icons.svg#x-icon"></use>
                </svg>
                X.com
              </a>
            </li>
            <li>
              <a href="https://bsky.app/profile/vite.dev" target="_blank">
                <svg
                  className="button-icon"
                  role="presentation"
                  aria-hidden="true"
                >
                  <use href="/icons.svg#bluesky-icon"></use>
                </svg>
                Bluesky
              </a>
            </li>
          </ul>
        </div>
      </section>

      <div className="ticks"></div>
      <section id="spacer"></section>
    </>
  )
}

export default App
