import { useEffect, useState } from 'react'
import {
  CalendarDays,
  CircleAlert,
  CircleCheck,
  Eye,
  EyeOff,
  KeyRound,
  Lock,
  LockKeyhole,
  Mail,
  RefreshCw,
  ShieldCheck,
  User,
  UserRound,
} from 'lucide-react'
import api, { getErrorMessage } from '../../../api/api.js'
import AppShell from '../../../components/AppShell.jsx'
import { useAuth } from '../../auth/hooks/useAuth.js'
import { EMAIL_PATTERN, MIN_PASSWORD } from '../../auth/validation.js'

const INPUT_CLASS =
  'st-autofill w-full rounded-lg bg-st-low/60 py-2.5 text-sm text-st-navy outline-none ring-1 ring-st-container transition placeholder:text-st-outline focus:bg-white focus:ring-2 focus:ring-st-blue-dark disabled:opacity-60'
const BUTTON_CLASS =
  'inline-flex items-center justify-center gap-1.5 rounded-lg bg-st-navy px-5 py-2.5 text-sm font-semibold text-white shadow-md shadow-st-navy/20 transition hover:bg-st-blue-dark disabled:cursor-not-allowed disabled:opacity-70'

function formatDate(value) {
  return value ? new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—'
}

function initials(name = '') {
  const parts = name.trim().split(/\s+/).filter(Boolean)
  return ((parts[0]?.[0] || '') + (parts.length > 1 ? parts[parts.length - 1][0] : '')).toUpperCase() || '?'
}

function Card({ className = '', children }) {
  return <section className={`rounded-xl bg-white p-6 shadow-sm ring-1 ring-st-container/60 ${className}`}>{children}</section>
}

function CardHeader({ icon: Icon, title, text }) {
  return (
    <div className="mb-5 flex items-start gap-3">
      <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-st-low text-st-blue-dark">
        <Icon className="h-5 w-5" aria-hidden="true" />
      </span>
      <div>
        <h2 className="font-manrope text-xl font-semibold text-st-navy">{title}</h2>
        <p className="text-sm text-st-muted">{text}</p>
      </div>
    </div>
  )
}

function Banner({ tone, children }) {
  if (!children) return null
  const success = tone === 'success'
  const Icon = success ? CircleCheck : CircleAlert
  return (
    <div
      role={success ? 'status' : 'alert'}
      className={`mb-4 flex items-start gap-2 rounded-lg p-3 text-sm ${success ? 'bg-st-fixed text-st-navy' : 'bg-st-error-bg text-st-error-ink'}`}
    >
      <Icon className="mt-0.5 h-[18px] w-[18px] shrink-0" aria-hidden="true" /> {children}
    </div>
  )
}

function Field({ id, label, icon: Icon, error, toggle, ...inputProps }) {
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-sm font-semibold text-st-navy">{label}</label>
      <div className="relative flex items-center">
        <Icon className="pointer-events-none absolute left-3 h-[18px] w-[18px] text-st-outline" aria-hidden="true" />
        <input
          id={id}
          aria-invalid={Boolean(error)}
          aria-describedby={error ? `${id}-error` : undefined}
          className={`${INPUT_CLASS} pl-10 ${toggle ? 'pr-10' : 'pr-4'} ${error ? 'ring-st-error' : ''}`}
          {...inputProps}
        />
        {toggle}
      </div>
      {error && <p id={`${id}-error`} className="mt-1 text-xs font-semibold text-st-error">{error}</p>}
    </div>
  )
}

function PasswordToggle({ shown, onToggle }) {
  return (
    <button
      type="button"
      onClick={onToggle}
      className="absolute right-3 flex items-center text-st-outline transition hover:text-st-navy"
      aria-label={shown ? 'Hide passwords' : 'Show passwords'}
    >
      {shown ? <EyeOff className="h-[18px] w-[18px]" aria-hidden="true" /> : <Eye className="h-[18px] w-[18px]" aria-hidden="true" />}
    </button>
  )
}

function AccountSummary({ profile }) {
  const isAdmin = profile.role === 'ADMIN'
  const details = [
    { icon: Mail, label: 'Email', value: profile.email },
    { icon: CalendarDays, label: 'Member since', value: formatDate(profile.created_at) },
    { icon: RefreshCw, label: 'Last updated', value: formatDate(profile.updated_at) },
  ]

  return (
    <Card className="relative overflow-hidden lg:col-span-4">
      <div className="pointer-events-none absolute inset-x-0 top-0 h-24 bg-gradient-to-r from-st-navy-2 to-st-blue" />
      <div className="relative flex flex-col items-center pt-8 text-center">
        <span className="flex h-24 w-24 items-center justify-center rounded-full bg-st-navy font-manrope text-3xl font-bold text-white ring-4 ring-white">
          {initials(profile.name)}
        </span>
        <h2 className="mt-3 font-manrope text-xl font-bold text-st-navy">{profile.name}</h2>
        <p className="break-all text-sm text-st-muted">{profile.email}</p>
        <div className="mt-3 flex flex-wrap justify-center gap-2">
          <span className={`rounded-full px-2.5 py-0.5 text-[0.6875rem] font-bold uppercase tracking-wider ${isAdmin ? 'bg-st-navy-2 text-white' : 'bg-st-fixed text-st-navy'}`}>
            {profile.role}
          </span>
          <span className={`flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[0.6875rem] font-bold ${profile.is_active ? 'bg-st-container text-st-blue-dark' : 'bg-st-error-bg text-st-error-ink'}`}>
            <span className={`h-1.5 w-1.5 rounded-full ${profile.is_active ? 'bg-st-blue' : 'bg-st-error'}`} />
            {profile.is_active ? 'Active' : 'Inactive'}
          </span>
        </div>
      </div>

      <ul className="mt-6 flex flex-col gap-2">
        {details.map(({ icon: Icon, label, value }) => (
          <li key={label} className="flex items-center gap-3 rounded-lg bg-st-low px-3 py-2.5">
            <Icon className="h-4 w-4 shrink-0 text-st-blue-dark" aria-hidden="true" />
            <div className="min-w-0">
              <p className="text-[0.6875rem] font-bold uppercase tracking-wider text-st-outline">{label}</p>
              <p className="truncate text-sm font-semibold text-st-ink" title={value}>{value}</p>
            </div>
          </li>
        ))}
      </ul>

      <div className="mt-4 flex items-start gap-2 rounded-lg bg-st-low/60 p-3 text-[0.6875rem] font-semibold text-st-muted">
        <ShieldCheck className="h-4 w-4 shrink-0 text-st-blue-dark" aria-hidden="true" />
        <span>Your role can only be changed by an administrator.</span>
      </div>
    </Card>
  )
}

export default function Profile() {
  const { setUser } = useAuth()
  const [profile, setProfile] = useState(null)
  const [loadError, setLoadError] = useState('')
  const [notice, setNotice] = useState('')

  useEffect(() => {
    let active = true
    api
      .get('/users/profile')
      .then(({ data }) => active && setProfile(data.user))
      .catch((err) => active && setLoadError(getErrorMessage(err, 'Unable to load your profile.')))
    return () => {
      active = false
    }
  }, [])

  function handleSaved(updated) {
    setProfile(updated)
    setNotice('Profile updated.')
    setUser({ id: updated.id, name: updated.name, email: updated.email, role: updated.role })
  }

  return (
    <AppShell title="Profile">
      <div className="flex w-full flex-col gap-8 px-4 py-8 md:px-8">
        <div className="flex flex-col gap-1">
          <span className="w-fit rounded-full bg-st-container px-2 py-0.5 text-[0.6875rem] font-bold uppercase tracking-widest text-st-blue-dark">
            Account Settings
          </span>
          <h1 className="font-manrope text-[1.75rem] font-bold tracking-tight text-st-navy lg:text-4xl">My Profile</h1>
          <p className="max-w-2xl text-base text-st-muted">Manage your ScamTrace account details and password.</p>
        </div>

        {loadError && <Banner tone="error">{loadError}</Banner>}
        <Banner tone="success">{notice}</Banner>
        {!profile && !loadError && <p className="text-sm text-st-muted">Loading profile…</p>}

        {profile && (
          <div className="grid grid-cols-1 items-start gap-6 lg:grid-cols-12">
            <AccountSummary profile={profile} />
            <div className="flex flex-col gap-6 lg:col-span-8">
              <EditProfile key={profile.updated_at} profile={profile} onSaved={handleSaved} />
              <ChangePassword />
            </div>
          </div>
        )}
      </div>
    </AppShell>
  )
}

function EditProfile({ profile, onSaved }) {
  const [form, setForm] = useState({ name: profile.name, email: profile.email })
  const [errors, setErrors] = useState({})
  const [message, setMessage] = useState({ tone: 'error', text: '' })
  const [saving, setSaving] = useState(false)

  async function handleSubmit(event) {
    event.preventDefault()
    const found = {}
    if (form.name.trim().length < 2 || form.name.trim().length > 100) found.name = 'Name must be 2–100 characters.'
    if (!EMAIL_PATTERN.test(form.email.trim())) found.email = 'Enter a valid email address.'
    setErrors(found)
    setMessage({ tone: 'error', text: '' })
    if (Object.keys(found).length) return

    const changes = {}
    if (form.name.trim() !== profile.name) changes.name = form.name.trim()
    if (form.email.trim().toLowerCase() !== profile.email) changes.email = form.email.trim()
    if (!Object.keys(changes).length) {
      setMessage({ tone: 'success', text: 'No changes to save.' })
      return
    }

    setSaving(true)
    try {
      const { data } = await api.patch('/users/profile', changes)
      onSaved(data.user)
    } catch (err) {
      if (err.response?.data?.errors) setErrors(err.response.data.errors)
      setMessage({ tone: 'error', text: getErrorMessage(err, 'Unable to update your profile.') })
      setSaving(false)
    }
  }

  return (
    <Card>
      <CardHeader icon={UserRound} title="Edit Profile" text="Update your name and email address." />
      <Banner tone={message.tone}>{message.text}</Banner>
      <form onSubmit={handleSubmit} noValidate className="flex flex-col gap-4">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <Field
            id="profile-name"
            label="Full Name"
            icon={User}
            autoComplete="name"
            value={form.name}
            error={errors.name}
            disabled={saving}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
          />
          <Field
            id="profile-email"
            label="Email Address"
            icon={Mail}
            type="email"
            autoComplete="email"
            value={form.email}
            error={errors.email}
            disabled={saving}
            onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))}
          />
        </div>
        <div className="flex justify-end">
          <button type="submit" className={BUTTON_CLASS} disabled={saving}>{saving ? 'Saving…' : 'Save Changes'}</button>
        </div>
      </form>
    </Card>
  )
}

function ChangePassword() {
  const empty = { currentPassword: '', newPassword: '', confirmPassword: '' }
  const [form, setForm] = useState(empty)
  const [errors, setErrors] = useState({})
  const [message, setMessage] = useState({ tone: 'error', text: '' })
  const [saving, setSaving] = useState(false)
  const [shown, setShown] = useState(false)

  function update(field) {
    return (event) => setForm((current) => ({ ...current, [field]: event.target.value }))
  }

  async function handleSubmit(event) {
    event.preventDefault()
    const found = {}
    if (!form.currentPassword) found.currentPassword = 'Current password is required.'
    if (form.newPassword.length < MIN_PASSWORD) found.newPassword = `At least ${MIN_PASSWORD} characters.`
    if (form.confirmPassword !== form.newPassword) found.confirmPassword = 'Passwords do not match.'
    setErrors(found)
    setMessage({ tone: 'error', text: '' })
    if (Object.keys(found).length) return

    setSaving(true)
    try {
      await api.patch('/users/password', { currentPassword: form.currentPassword, newPassword: form.newPassword })
      setForm(empty)
      setMessage({ tone: 'success', text: 'Password updated.' })
    } catch (err) {
      setMessage({ tone: 'error', text: getErrorMessage(err, 'Unable to change your password.') })
    } finally {
      setSaving(false)
    }
  }

  const type = shown ? 'text' : 'password'
  const toggle = <PasswordToggle shown={shown} onToggle={() => setShown((value) => !value)} />

  return (
    <Card>
      <CardHeader icon={KeyRound} title="Change Password" text="Your current password is required to set a new one." />
      <Banner tone={message.tone}>{message.text}</Banner>
      <form onSubmit={handleSubmit} noValidate className="flex flex-col gap-4">
        <Field
          id="pw-current"
          label="Current Password"
          icon={Lock}
          type={type}
          autoComplete="current-password"
          value={form.currentPassword}
          onChange={update('currentPassword')}
          error={errors.currentPassword}
          disabled={saving}
          toggle={toggle}
        />
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <Field
            id="pw-new"
            label="New Password"
            icon={LockKeyhole}
            type={type}
            autoComplete="new-password"
            placeholder={`At least ${MIN_PASSWORD} characters`}
            value={form.newPassword}
            onChange={update('newPassword')}
            error={errors.newPassword}
            disabled={saving}
          />
          <Field
            id="pw-confirm"
            label="Confirm New Password"
            icon={LockKeyhole}
            type={type}
            autoComplete="new-password"
            value={form.confirmPassword}
            onChange={update('confirmPassword')}
            error={errors.confirmPassword}
            disabled={saving}
          />
        </div>
        <div className="flex justify-end">
          <button type="submit" className={BUTTON_CLASS} disabled={saving}>{saving ? 'Updating…' : 'Update Password'}</button>
        </div>
      </form>
    </Card>
  )
}
