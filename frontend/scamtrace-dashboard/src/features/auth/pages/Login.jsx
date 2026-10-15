import { useState } from 'react'
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom'
import { getErrorMessage } from '../../../api/api.js'
import { AuthLayout, FormAlert, FormField, SubmitButton } from '../components/AuthLayout.jsx'
import AuthLoading from '../components/AuthLoading.jsx'
import { useAuth } from '../hooks/useAuth.js'
import { EMAIL_PATTERN } from '../validation.js'

function validate({ email, password }) {
  const errors = {}
  if (!email.trim()) errors.email = 'Email is required.'
  else if (!EMAIL_PATTERN.test(email.trim())) errors.email = 'Enter a valid email address.'
  if (!password) errors.password = 'Password is required.'
  return errors
}

export default function Login() {
  const { isAuthenticated, loading, login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [form, setForm] = useState({ email: '', password: '' })
  const [errors, setErrors] = useState({})
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const from = location.state?.from?.pathname || '/dashboard'

  if (loading) return <AuthLoading />
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
    <AuthLayout
      title="Sign in"
      subtitle="Access the ScamTrace threat detection and security intelligence dashboard."
      footer={<>New to ScamTrace? <Link to="/register" className="text-sky-400 hover:text-sky-300">Create an account</Link></>}
    >
      <form onSubmit={handleSubmit} noValidate className="space-y-4">
        <FormAlert>{error}</FormAlert>
        <FormField
          id="login-email" label="Email" type="email" autoComplete="email" placeholder="you@example.com"
          value={form.email} onChange={update('email')} error={errors.email} disabled={submitting}
        />
        <FormField
          id="login-password" label="Password" type="password" autoComplete="current-password"
          value={form.password} onChange={update('password')} error={errors.password} disabled={submitting}
        />
        <SubmitButton loading={submitting} loadingText="Signing in…">Sign in</SubmitButton>
      </form>
    </AuthLayout>
  )
}
