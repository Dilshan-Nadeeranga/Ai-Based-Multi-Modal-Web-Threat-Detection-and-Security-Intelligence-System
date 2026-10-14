import { useEffect, useState } from 'react'
import { UserCircle2 } from 'lucide-react'
import api, { getErrorMessage } from '../../../api/api.js'
import { FormAlert, FormField } from '../../auth/components/AuthLayout.jsx'
import { useAuth } from '../../auth/hooks/useAuth.js'
import { EMAIL_PATTERN, MIN_PASSWORD } from '../../auth/validation.js'

const card = 'bg-slate-900/80 border border-slate-800 rounded-xl p-6 space-y-4'
const button = 'rounded-lg bg-sky-600 hover:bg-sky-500 disabled:bg-sky-900 disabled:text-slate-400 px-4 py-2 text-sm font-semibold text-white transition-colors'

function formatDate(value) {
  return value ? new Date(value).toLocaleString() : '—'
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
    <main className="flex-1 w-full max-w-3xl mx-auto px-4 py-10 text-slate-100 space-y-6">
      <header className="flex items-center gap-3">
        <UserCircle2 className="w-9 h-9 text-sky-400" />
        <div>
          <h1 className="text-2xl font-semibold">My Profile</h1>
          <p className="text-sm text-slate-400">Manage your ScamTrace account details.</p>
        </div>
      </header>

      {loadError && <FormAlert>{loadError}</FormAlert>}
      <FormAlert tone="success">{notice}</FormAlert>
      {!profile && !loadError && <p className="text-sm text-slate-400">Loading profile…</p>}

      {profile && (
        <>
          <section className={card}>
            <h2 className="text-base font-semibold">Account</h2>
            <dl className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
              <div><dt className="text-slate-400">Name</dt><dd className="mt-0.5">{profile.name}</dd></div>
              <div><dt className="text-slate-400">Email</dt><dd className="mt-0.5 break-all">{profile.email}</dd></div>
              <div>
                <dt className="text-slate-400">Role</dt>
                <dd className="mt-1">
                  <span className={`px-2 py-0.5 rounded-full text-xs font-semibold border ${profile.role === 'ADMIN'
                    ? 'bg-purple-500/15 text-purple-300 border-purple-500/30'
                    : 'bg-sky-500/15 text-sky-300 border-sky-500/30'}`}>
                    {profile.role}
                  </span>
                </dd>
              </div>
              <div><dt className="text-slate-400">Member since</dt><dd className="mt-0.5">{formatDate(profile.created_at)}</dd></div>
            </dl>
          </section>

          <EditProfile key={profile.updated_at} profile={profile} onSaved={handleSaved} />
          <ChangePassword />
        </>
      )}
    </main>
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
    <section className={card}>
      <h2 className="text-base font-semibold">Edit profile</h2>
      <form onSubmit={handleSubmit} noValidate className="space-y-4">
        <FormAlert tone={message.tone}>{message.text}</FormAlert>
        <FormField id="profile-name" label="Name" value={form.name} error={errors.name} disabled={saving}
                   onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
        <FormField id="profile-email" label="Email" type="email" value={form.email} error={errors.email}
                   disabled={saving} onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))} />
        <button type="submit" className={button} disabled={saving}>{saving ? 'Saving…' : 'Save changes'}</button>
      </form>
    </section>
  )
}

function ChangePassword() {
  const empty = { currentPassword: '', newPassword: '', confirmPassword: '' }
  const [form, setForm] = useState(empty)
  const [errors, setErrors] = useState({})
  const [message, setMessage] = useState({ tone: 'error', text: '' })
  const [saving, setSaving] = useState(false)

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

  return (
    <section className={card}>
      <h2 className="text-base font-semibold">Change password</h2>
      <form onSubmit={handleSubmit} noValidate className="space-y-4">
        <FormAlert tone={message.tone}>{message.text}</FormAlert>
        <FormField id="pw-current" label="Current password" type="password" autoComplete="current-password"
                   value={form.currentPassword} onChange={update('currentPassword')} error={errors.currentPassword}
                   disabled={saving} />
        <FormField id="pw-new" label="New password" type="password" autoComplete="new-password"
                   value={form.newPassword} onChange={update('newPassword')} error={errors.newPassword} disabled={saving} />
        <FormField id="pw-confirm" label="Confirm new password" type="password" autoComplete="new-password"
                   value={form.confirmPassword} onChange={update('confirmPassword')} error={errors.confirmPassword}
                   disabled={saving} />
        <button type="submit" className={button} disabled={saving}>{saving ? 'Updating…' : 'Update password'}</button>
      </form>
    </section>
  )
}
