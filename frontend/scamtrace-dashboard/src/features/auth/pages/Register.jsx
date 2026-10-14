import { useState } from 'react'
import { Link, Navigate, useNavigate } from 'react-router-dom'
import { getErrorMessage } from '../../../api/api.js'
import { AuthLayout, FormAlert, FormField, SubmitButton } from '../components/AuthLayout.jsx'
import AuthLoading from '../components/AuthLoading.jsx'
import { useAuth } from '../hooks/useAuth.js'
import { EMAIL_PATTERN, MIN_PASSWORD } from '../validation.js'

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

/** Self-registration always creates a USER account; there is no role selection. */
export default function Register() {
  const { isAuthenticated, loading, register } = useAuth()
  const navigate = useNavigate()
  const [form, setForm] = useState({ name: '', email: '', password: '', confirmPassword: '' })
  const [errors, setErrors] = useState({})
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  if (loading) return <AuthLoading />
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

  return (
    <AuthLayout
      title="Create your account"
      subtitle="Register to submit analyses and repository audits."
      footer={<>Already have an account? <Link to="/login" className="text-sky-400 hover:text-sky-300">Sign in</Link></>}
    >
      <form onSubmit={handleSubmit} noValidate className="space-y-4">
        <FormAlert>{error}</FormAlert>
        <FormField
          id="register-name" label="Full Name" autoComplete="name" placeholder="Thamidu Peiris"
          value={form.name} onChange={update('name')} error={errors.name} disabled={submitting}
        />
        <FormField
          id="register-email" label="Email" type="email" autoComplete="email" placeholder="you@example.com"
          value={form.email} onChange={update('email')} error={errors.email} disabled={submitting}
        />
        <FormField
          id="register-password" label="Password" type="password" autoComplete="new-password"
          placeholder={`At least ${MIN_PASSWORD} characters`}
          value={form.password} onChange={update('password')} error={errors.password} disabled={submitting}
        />
        <FormField
          id="register-confirm" label="Confirm Password" type="password" autoComplete="new-password"
          value={form.confirmPassword} onChange={update('confirmPassword')} error={errors.confirmPassword}
          disabled={submitting}
        />
        <SubmitButton loading={submitting} loadingText="Creating account…">Create account</SubmitButton>
      </form>
    </AuthLayout>
  )
}
