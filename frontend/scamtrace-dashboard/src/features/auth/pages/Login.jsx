import { useState } from 'react'
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom'
import { ArrowRight, CircleAlert, Eye, EyeOff, KeyRound, Lock, Mail, ShieldCheck, X } from 'lucide-react'
import { getErrorMessage } from '../../../api/api.js'
import HomeFooter from '../../home/components/HomeFooter.jsx'
import HomeHeader from '../../home/components/HomeHeader.jsx'
import AuthLoading from '../components/AuthLoading.jsx'
import { useAuth } from '../hooks/useAuth.js'
import { EMAIL_PATTERN } from '../validation.js'

const INPUT_CLASS =
  'st-autofill w-full rounded-lg bg-st-low/60 py-2.5 text-sm text-st-navy outline-none ring-1 ring-st-container transition placeholder:text-st-outline focus:bg-white focus:ring-2 focus:ring-st-blue-dark disabled:opacity-60'

function validate({ email, password }) {
  const errors = {}
  if (!email.trim()) errors.email = 'Email is required.'
  else if (!EMAIL_PATTERN.test(email.trim())) errors.email = 'Enter a valid email address.'
  if (!password) errors.password = 'Password is required.'
  return errors
}

function IntroPanel() {
  return (
    <section className="flex flex-col justify-center lg:col-span-7">
      <span className="inline-flex w-fit items-center gap-1.5 rounded-full bg-st-highest px-3 py-1 text-xs font-semibold tracking-wider text-st-blue-dark">
        <span className="h-2 w-2 animate-ping rounded-full bg-st-blue-dark" />
        AI-POWERED THREAT INTELLIGENCE
      </span>
      <h1 className="mt-4 font-manrope text-[1.75rem] font-bold leading-tight tracking-tight text-st-navy lg:text-5xl">
        Secure Access to <span className="text-st-blue-dark">Smarter Threat Intelligence</span>
      </h1>
      <p className="mt-4 max-w-xl text-base text-st-muted lg:text-lg">
        Sign in to analyze suspicious URLs, social media scams, website visuals and source code repositories with
        ScamTrace&apos;s multi-modal analysis components.
      </p>
    </section>
  )
}

export default function Login() {
  const { isAuthenticated, loading, login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [form, setForm] = useState({ email: '', password: '' })
  const [errors, setErrors] = useState({})
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [showPassword, setShowPassword] = useState(false)

  const from = location.state?.from?.pathname || '/dashboard'

  if (loading) return <AuthLoading light />
  if (isAuthenticated && !submitting) return <Navigate to={from} replace />

  function update(field) {
    return (event) => setForm((current) => ({ ...current, [field]: event.target.value }))
  }

  async function handleSubmit(event) {
    event.preventDefault()
    const found = validate(form)
    setErrors(found)
    setError('')
    if (Object.keys(found).length) return

    setSubmitting(true)
    try {
      await login(form.email.trim(), form.password)
      navigate(from, { replace: true })
    } catch (err) {
      setError(getErrorMessage(err, 'Login failed. Please try again.'))
      setSubmitting(false)
    }
  }

  return (
    <div className="flex min-h-screen w-full flex-col justify-between bg-st-surface font-inter text-st-ink antialiased selection:bg-st-fixed selection:text-st-navy">
      <HomeHeader />

      <main className="st-blue-backdrop flex w-full flex-1 flex-col items-center justify-center px-4 pb-10 pt-28 md:px-8">
        <div className="mx-auto grid w-full max-w-7xl grid-cols-1 items-stretch gap-6 lg:grid-cols-12 lg:gap-8">
          <IntroPanel />

          <section className="order-first flex items-center justify-center lg:order-last lg:col-span-5">
            <div className="flex w-full max-w-md flex-col justify-between rounded-xl bg-white p-6 shadow-xl shadow-st-navy/5 md:p-10">
              <div>
                <div className="mb-2 flex items-center justify-between">
                  <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-st-low text-st-blue-dark">
                    <Lock className="h-5 w-5" aria-hidden="true" />
                  </span>
                </div>
                <h2 className="font-manrope text-2xl font-bold text-st-navy">Welcome Back</h2>
                <p className="mb-4 mt-0.5 text-sm text-st-muted">Sign in to your ScamTrace account.</p>

                {error && (
                  <div role="alert" className="mb-4 flex items-start gap-2 rounded-lg bg-st-error-bg p-3 text-st-error-ink">
                    <CircleAlert className="mt-0.5 h-[18px] w-[18px] shrink-0" aria-hidden="true" />
                    <div className="flex-1">
                      <p className="text-[0.6875rem] font-bold">Sign-in failed</p>
                      <p className="text-xs">{error}</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => setError('')}
                      className="text-st-error-ink/70 hover:text-st-error-ink"
                      aria-label="Dismiss error"
                    >
                      <X className="h-4 w-4" aria-hidden="true" />
                    </button>
                  </div>
                )}

                <form onSubmit={handleSubmit} noValidate className="space-y-4">
                  <div>
                    <label htmlFor="login-email" className="mb-1 block text-sm font-semibold text-st-navy">
                      Email Address <span className="text-st-error">*</span>
                    </label>
                    <div className="relative flex items-center">
                      <Mail className="pointer-events-none absolute left-3 h-[18px] w-[18px] text-st-outline" aria-hidden="true" />
                      <input
                        id="login-email"
                        type="email"
                        autoComplete="email"
                        placeholder="you@example.com"
                        value={form.email}
                        onChange={update('email')}
                        disabled={submitting}
                        aria-invalid={Boolean(errors.email)}
                        aria-describedby={errors.email ? 'login-email-error' : undefined}
                        className={`${INPUT_CLASS} pl-10 pr-4 ${errors.email ? 'ring-st-error' : ''}`}
                      />
                    </div>
                    {errors.email && (
                      <p id="login-email-error" className="mt-1 text-xs font-semibold text-st-error">{errors.email}</p>
                    )}
                  </div>

                  <div>
                    <label htmlFor="login-password" className="mb-1 block text-sm font-semibold text-st-navy">
                      Password <span className="text-st-error">*</span>
                    </label>
                    <div className="relative flex items-center">
                      <KeyRound className="pointer-events-none absolute left-3 h-[18px] w-[18px] text-st-outline" aria-hidden="true" />
                      <input
                        id="login-password"
                        type={showPassword ? 'text' : 'password'}
                        autoComplete="current-password"
                        placeholder="••••••••••••"
                        value={form.password}
                        onChange={update('password')}
                        disabled={submitting}
                        aria-invalid={Boolean(errors.password)}
                        aria-describedby={errors.password ? 'login-password-error' : undefined}
                        className={`${INPUT_CLASS} pl-10 pr-10 ${errors.password ? 'ring-st-error' : ''}`}
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword((value) => !value)}
                        className="absolute right-3 flex items-center text-st-outline transition hover:text-st-navy"
                        aria-label={showPassword ? 'Hide password' : 'Show password'}
                      >
                        {showPassword
                          ? <EyeOff className="h-[18px] w-[18px]" aria-hidden="true" />
                          : <Eye className="h-[18px] w-[18px]" aria-hidden="true" />}
                      </button>
                    </div>
                    {errors.password && (
                      <p id="login-password-error" className="mt-1 text-xs font-semibold text-st-error">{errors.password}</p>
                    )}
                  </div>

                  <button
                    type="submit"
                    disabled={submitting}
                    className="flex w-full items-center justify-center gap-1.5 rounded-lg bg-st-navy px-4 py-3 text-sm font-semibold text-white shadow-md shadow-st-navy/20 transition duration-200 hover:bg-st-blue-dark disabled:cursor-not-allowed disabled:opacity-80"
                  >
                    {submitting ? (
                      <>
                        <span className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                        Signing in…
                      </>
                    ) : (
                      <>
                        Sign In
                        <ArrowRight className="h-[18px] w-[18px]" aria-hidden="true" />
                      </>
                    )}
                  </button>
                </form>

                <p className="mt-6 text-center text-sm font-semibold text-st-muted">
                  Don&apos;t have an account?{' '}
                  <Link to="/register" className="font-bold text-st-blue-dark hover:underline">Create Account</Link>
                </p>
              </div>

              <div className="mt-6 flex items-center gap-2 rounded-lg bg-st-low/50 p-3">
                <ShieldCheck className="h-[18px] w-[18px] shrink-0 text-st-blue-dark" aria-hidden="true" />
                <p className="text-[0.6875rem] font-bold leading-tight text-st-muted">
                  Your session is kept in an HttpOnly cookie that scripts cannot read, and it expires after one hour.
                </p>
              </div>
            </div>
          </section>
        </div>
      </main>

      <HomeFooter />
    </div>
  )
}
