import { useState } from 'react'
import { Link, Navigate, useNavigate } from 'react-router-dom'
import {
  ArrowRight,
  BadgeCheck,
  Check,
  CircleAlert,
  CircleCheck,
  Circle,
  Code,
  Eye,
  EyeOff,
  FileCode,
  History,
  Image,
  Info,
  Link as LinkIcon,
  Lock,
  LockKeyhole,
  Mail,
  ShieldCheck,
  User,
  X,
} from 'lucide-react'
import { getErrorMessage } from '../../../api/api.js'
import HomeFooter from '../../home/components/HomeFooter.jsx'
import HomeHeader from '../../home/components/HomeHeader.jsx'
import AuthLoading from '../components/AuthLoading.jsx'
import { useAuth } from '../hooks/useAuth.js'
import { EMAIL_PATTERN, MIN_PASSWORD } from '../validation.js'

const INPUT_CLASS =
  'st-autofill w-full rounded-lg bg-st-low/60 py-2.5 text-sm text-st-navy outline-none ring-1 ring-st-container transition placeholder:text-st-outline focus:bg-white focus:ring-2 focus:ring-st-blue-dark disabled:opacity-60'

const FEATURES = [
  { icon: LinkIcon, text: 'Analyze suspicious URLs and domains' },
  { icon: Code, text: 'Inspect web page content and scripts' },
  { icon: Image, text: 'Check social media posts and website screenshots for visual threats' },
  { icon: FileCode, text: 'Audit source code repositories for vulnerabilities' },
  { icon: History, text: 'Review your previous analyses and audits' },
]

const STRENGTH_LEVELS = [
  { label: 'None', text: 'text-st-outline', bar: 'bg-st-container' },
  { label: 'Weak', text: 'text-st-error', bar: 'bg-st-error' },
  { label: 'Fair', text: 'text-amber-600', bar: 'bg-amber-500' },
  { label: 'Good', text: 'text-st-blue-dark', bar: 'bg-st-blue-dark' },
  { label: 'Strong', text: 'text-st-blue', bar: 'bg-st-blue' },
]

function validate({ name, email, password, confirmPassword }) {
  const errors = {}
  if (!name.trim()) errors.name = 'Full name is required.'
  else if (name.trim().length < 2 || name.trim().length > 100) errors.name = 'Name must be 2–100 characters.'
  if (!email.trim()) errors.email = 'Email is required.'
  else if (!EMAIL_PATTERN.test(email.trim())) errors.email = 'Enter a valid email address.'
  if (!password) errors.password = 'Password is required.'
  else if (password.length < MIN_PASSWORD) errors.password = `Password must be at least ${MIN_PASSWORD} characters.`
  if (!confirmPassword) errors.confirmPassword = 'Please confirm your password.'
  else if (confirmPassword !== password) errors.confirmPassword = 'Passwords do not match.'
  return errors
}

function passwordChecks(password) {
  return {
    length: password.length >= MIN_PASSWORD,
    numberOrSymbol: /[^A-Za-z]/.test(password),
    upper: /[A-Z]/.test(password),
  }
}

function strengthScore(password, checks) {
  if (!password) return 0
  let score = 1
  if (checks.length) score += 1
  if (checks.length && checks.numberOrSymbol) score += 1
  if (checks.length && checks.upper && password.length >= 10) score += 1
  return score
}

function IntroPanel() {
  return (
    <section className="relative flex flex-col gap-6 overflow-hidden rounded-3xl bg-st-low/90 p-6 shadow-sm ring-1 ring-st-container lg:col-span-7 lg:p-10">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(#005bb0_1px,transparent_1px)] opacity-20 [background-size:16px_16px]" />

      <div className="relative z-10 flex flex-col gap-4">
        <span className="inline-flex w-fit items-center gap-1.5 rounded-full bg-white px-3 py-1 text-[0.6875rem] font-bold uppercase tracking-wider text-st-blue-dark shadow-sm">
          <span className="h-2 w-2 animate-pulse rounded-full bg-st-blue" />
          Join ScamTrace
        </span>
        <h1 className="font-manrope text-[1.75rem] font-extrabold leading-tight tracking-tight text-st-navy lg:text-4xl">
          Start Analyzing <span className="text-st-blue">Digital Threats</span> with Confidence
        </h1>
        <p className="text-base text-st-muted">
          Create an account to submit suspicious content, review threat reports and keep track of your ScamTrace
          analysis history.
        </p>
      </div>

      <ul className="relative z-10 flex flex-col gap-3">
        {FEATURES.map(({ icon: Icon, text }) => (
          <li key={text} className="flex items-center gap-3">
            <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-st-blue-dark/10 text-st-blue-dark">
              <Icon className="h-[17px] w-[17px]" aria-hidden="true" />
            </span>
            <span className="text-sm font-medium text-st-ink">{text}</span>
          </li>
        ))}
      </ul>

      <div className="relative z-10 mt-auto flex items-center gap-1.5 pt-2 text-[0.6875rem] font-bold text-st-muted">
        <BadgeCheck className="h-4 w-4 shrink-0 text-st-blue-dark" aria-hidden="true" />
        <span>
          New accounts are created with the standard <strong className="text-st-ink">User</strong> role.
        </span>
      </div>
    </section>
  )
}

function FieldError({ id, children }) {
  if (!children) return null
  return <p id={id} className="mt-1 text-xs font-semibold text-st-error">{children}</p>
}

function PasswordToggle({ shown, onToggle, label }) {
  return (
    <button
      type="button"
      onClick={onToggle}
      className="absolute right-3 flex items-center text-st-outline transition hover:text-st-navy"
      aria-label={shown ? `Hide ${label}` : `Show ${label}`}
    >
      {shown
        ? <EyeOff className="h-[18px] w-[18px]" aria-hidden="true" />
        : <Eye className="h-[18px] w-[18px]" aria-hidden="true" />}
    </button>
  )
}

function Requirement({ met, children }) {
  const Icon = met ? CircleCheck : Circle
  return (
    <span className={`flex items-center gap-1 ${met ? 'text-st-blue-dark' : 'text-st-outline'}`}>
      <Icon className="h-3.5 w-3.5" aria-hidden="true" />
      {children}
    </span>
  )
}

function StrengthMeter({ password }) {
  const checks = passwordChecks(password)
  const score = strengthScore(password, checks)
  const level = STRENGTH_LEVELS[score]

  return (
    <div className="mt-2 flex flex-col gap-1.5" aria-live="polite">
      <div className="flex items-center justify-between text-[0.6875rem] font-bold">
        <span className="text-st-muted">Password strength:</span>
        <span className={level.text}>{level.label}</span>
      </div>
      <div className="grid h-1.5 w-full grid-cols-4 gap-1.5">
        {[1, 2, 3, 4].map((step) => (
          <div key={step} className={`rounded-full transition-colors ${step <= score ? level.bar : 'bg-st-container'}`} />
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 pt-0.5 text-[0.6875rem] font-semibold">
        <Requirement met={checks.length}>At least {MIN_PASSWORD} characters (required)</Requirement>
        <Requirement met={checks.numberOrSymbol}>A number or symbol</Requirement>
        <Requirement met={checks.upper}>An uppercase letter</Requirement>
      </div>
    </div>
  )
}

function MatchBadge({ password, confirmPassword }) {
  if (!confirmPassword) return null
  if (password === confirmPassword) {
    return (
      <span className="flex items-center gap-1 rounded-full bg-st-fixed px-2 py-0.5 text-[0.6875rem] font-bold text-st-blue-dark">
        <Check className="h-3 w-3" aria-hidden="true" /> Passwords match
      </span>
    )
  }
  return (
    <span className="flex items-center gap-1 rounded-full bg-st-error-bg px-2 py-0.5 text-[0.6875rem] font-bold text-st-error">
      <X className="h-3 w-3" aria-hidden="true" /> Do not match
    </span>
  )
}

/** Self-registration always creates a USER account; there is no role selection. */
export default function Register() {
  const { isAuthenticated, loading, register } = useAuth()
  const navigate = useNavigate()
  const [form, setForm] = useState({ name: '', email: '', password: '', confirmPassword: '' })
  const [errors, setErrors] = useState({})
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirm, setShowConfirm] = useState(false)

  if (loading) return <AuthLoading light />
  if (isAuthenticated && !submitting) return <Navigate to="/dashboard" replace />

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
      await register(form.name.trim(), form.email.trim(), form.password)
      navigate('/dashboard', { replace: true })
    } catch (err) {
      const fieldErrors = err.response?.data?.errors
      if (fieldErrors) setErrors(fieldErrors)
      setError(getErrorMessage(err, 'Registration failed. Please try again.'))
      setSubmitting(false)
    }
  }

  function inputProps(field, id) {
    return {
      id,
      value: form[field],
      onChange: update(field),
      disabled: submitting,
      'aria-invalid': Boolean(errors[field]),
      'aria-describedby': errors[field] ? `${id}-error` : undefined,
    }
  }

  function inputClass(field, padding) {
    return `${INPUT_CLASS} ${padding} ${errors[field] ? 'ring-st-error' : ''}`
  }

  return (
    <div className="flex min-h-screen w-full flex-col justify-between bg-st-surface font-inter text-st-ink antialiased selection:bg-st-fixed selection:text-st-navy">
      <HomeHeader />

      <main className="st-blue-backdrop flex w-full flex-1 flex-col items-center justify-center px-4 pb-10 pt-28 md:px-8">
        <div className="mx-auto grid w-full max-w-7xl grid-cols-1 items-stretch gap-6 lg:grid-cols-12 lg:gap-10">
          <IntroPanel />

          <section className="order-first mx-auto flex w-full max-w-lg flex-col rounded-2xl bg-white p-6 shadow-xl shadow-st-navy/5 lg:order-last lg:col-span-5 lg:p-8">
            <div className="mb-6 flex flex-col gap-1">
              <h2 className="font-manrope text-2xl font-bold text-st-navy">Create Your Account</h2>
              <p className="text-sm text-st-muted">Get started with ScamTrace multi-modal threat analysis.</p>
            </div>

            {error && (
              <div role="alert" className="mb-4 flex items-start gap-2 rounded-lg bg-st-error-bg p-3 text-st-error-ink">
                <CircleAlert className="mt-0.5 h-[18px] w-[18px] shrink-0" aria-hidden="true" />
                <div className="flex-1">
                  <p className="text-[0.6875rem] font-bold">Registration failed</p>
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

            <form onSubmit={handleSubmit} noValidate className="flex flex-col gap-4">
              <div>
                <label htmlFor="register-name" className="mb-1 block text-sm font-semibold text-st-navy">
                  Full Name <span className="text-st-error">*</span>
                </label>
                <div className="relative flex items-center">
                  <User className="pointer-events-none absolute left-3 h-[18px] w-[18px] text-st-outline" aria-hidden="true" />
                  <input
                    {...inputProps('name', 'register-name')}
                    type="text"
                    autoComplete="name"
                    placeholder="Your full name"
                    className={inputClass('name', 'pl-10 pr-4')}
                  />
                </div>
                <FieldError id="register-name-error">{errors.name}</FieldError>
              </div>

              <div>
                <label htmlFor="register-email" className="mb-1 block text-sm font-semibold text-st-navy">
                  Email Address <span className="text-st-error">*</span>
                </label>
                <div className="relative flex items-center">
                  <Mail className="pointer-events-none absolute left-3 h-[18px] w-[18px] text-st-outline" aria-hidden="true" />
                  <input
                    {...inputProps('email', 'register-email')}
                    type="email"
                    autoComplete="email"
                    placeholder="you@example.com"
                    className={inputClass('email', 'pl-10 pr-4')}
                  />
                </div>
                <FieldError id="register-email-error">{errors.email}</FieldError>
              </div>

              <div>
                <label htmlFor="register-password" className="mb-1 block text-sm font-semibold text-st-navy">
                  Password <span className="text-st-error">*</span>
                </label>
                <div className="relative flex items-center">
                  <Lock className="pointer-events-none absolute left-3 h-[18px] w-[18px] text-st-outline" aria-hidden="true" />
                  <input
                    {...inputProps('password', 'register-password')}
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="new-password"
                    placeholder={`Create a password (min. ${MIN_PASSWORD} characters)`}
                    className={inputClass('password', 'pl-10 pr-10')}
                  />
                  <PasswordToggle shown={showPassword} onToggle={() => setShowPassword((v) => !v)} label="password" />
                </div>
                <FieldError id="register-password-error">{errors.password}</FieldError>
                <StrengthMeter password={form.password} />
              </div>

              <div>
                <div className="mb-1 flex items-center justify-between gap-2">
                  <label htmlFor="register-confirm" className="block text-sm font-semibold text-st-navy">
                    Confirm Password <span className="text-st-error">*</span>
                  </label>
                  <MatchBadge password={form.password} confirmPassword={form.confirmPassword} />
                </div>
                <div className="relative flex items-center">
                  <LockKeyhole className="pointer-events-none absolute left-3 h-[18px] w-[18px] text-st-outline" aria-hidden="true" />
                  <input
                    {...inputProps('confirmPassword', 'register-confirm')}
                    type={showConfirm ? 'text' : 'password'}
                    autoComplete="new-password"
                    placeholder="Re-enter your password"
                    className={inputClass('confirmPassword', 'pl-10 pr-10')}
                  />
                  <PasswordToggle shown={showConfirm} onToggle={() => setShowConfirm((v) => !v)} label="confirm password" />
                </div>
                <FieldError id="register-confirm-error">{errors.confirmPassword}</FieldError>
              </div>

              <div className="flex items-center gap-2 rounded-lg bg-st-low/60 p-2.5 text-[0.6875rem] font-semibold text-st-muted">
                <Info className="h-4 w-4 shrink-0 text-st-blue-dark" aria-hidden="true" />
                <span>
                  All new registrations are created as standard <strong className="text-st-ink">User</strong> accounts.
                </span>
              </div>

              <button
                type="submit"
                disabled={submitting}
                className="flex w-full items-center justify-center gap-1.5 rounded-lg bg-st-navy px-4 py-3 text-sm font-semibold text-white shadow-md shadow-st-navy/20 transition duration-200 hover:bg-st-blue-dark disabled:cursor-not-allowed disabled:opacity-80"
              >
                {submitting ? (
                  <>
                    <span className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                    Creating account…
                  </>
                ) : (
                  <>
                    Create Account
                    <ArrowRight className="h-[18px] w-[18px]" aria-hidden="true" />
                  </>
                )}
              </button>

              <p className="text-center text-sm font-semibold text-st-muted">
                Already have an account?{' '}
                <Link to="/login" className="font-bold text-st-blue-dark hover:underline">Sign In</Link>
              </p>
            </form>

            <div className="mt-6 flex items-center gap-2 rounded-lg bg-st-low/50 p-3">
              <ShieldCheck className="h-[18px] w-[18px] shrink-0 text-st-blue-dark" aria-hidden="true" />
              <p className="text-[0.6875rem] font-bold leading-tight text-st-muted">
                Passwords are stored as salted bcrypt hashes. After registration you are signed in with an HttpOnly
                session cookie.
              </p>
            </div>
          </section>
        </div>
      </main>

      <HomeFooter />
    </div>
  )
}
