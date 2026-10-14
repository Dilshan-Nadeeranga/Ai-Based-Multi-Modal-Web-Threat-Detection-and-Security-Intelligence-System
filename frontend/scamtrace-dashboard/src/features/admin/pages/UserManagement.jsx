import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Users } from 'lucide-react'
import api, { getErrorMessage } from '../../../api/api.js'
import { FormAlert } from '../../auth/components/AuthLayout.jsx'
import { useAuth } from '../../auth/hooks/useAuth.js'
import ConfirmDialog from '../components/ConfirmDialog.jsx'

const actionButton = 'rounded-md border px-2.5 py-1 text-xs font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed'

function RoleBadge({ role }) {
  const style = role === 'ADMIN'
    ? 'bg-purple-500/15 text-purple-300 border-purple-500/30'
    : 'bg-sky-500/15 text-sky-300 border-sky-500/30'
  return <span className={`px-2 py-0.5 rounded-full text-xs font-semibold border ${style}`}>{role}</span>
}

function StatusBadge({ active }) {
  const style = active
    ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
    : 'bg-red-500/15 text-red-300 border-red-500/30'
  return <span className={`px-2 py-0.5 rounded-full text-xs font-semibold border ${style}`}>{active ? 'Active' : 'Disabled'}</span>
}

function describe(action) {
  const { user, type } = action
  if (type === 'status') {
    return user.is_active
      ? { title: 'Deactivate user?', message: `${user.name} (${user.email}) will be signed out and cannot log in until reactivated.`, label: 'Deactivate', danger: true }
      : { title: 'Activate user?', message: `${user.name} (${user.email}) will be able to log in again.`, label: 'Activate', danger: false }
  }
  return user.role === 'USER'
    ? { title: 'Grant administrator role?', message: `${user.name} will be able to manage all users and view all analyses.`, label: 'Make ADMIN', danger: true }
    : { title: 'Remove administrator role?', message: `${user.name} will become a regular USER.`, label: 'Make USER', danger: false }
}

export default function UserManagement() {
  const { user: currentUser } = useAuth()
  const [users, setUsers] = useState(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [pending, setPending] = useState(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let active = true
    api
      .get('/admin/users')
      .then(({ data }) => active && setUsers(data.users))
      .catch((err) => active && setError(getErrorMessage(err, 'Unable to load users.')))
    return () => {
      active = false
    }
  }, [])

  const cancel = useCallback(() => setPending(null), [])

  async function confirm() {
    const { user, type } = pending
    setBusy(true)
    setError('')
    try {
      const { data } = type === 'status'
        ? await api.patch(`/admin/users/${user.id}/status`, { is_active: !user.is_active })
        : await api.patch(`/admin/users/${user.id}/role`, { role: user.role === 'USER' ? 'ADMIN' : 'USER' })
      setUsers((list) => list.map((item) => (item.id === data.user.id ? data.user : item)))
      setNotice(`${data.message}: ${data.user.email}`)
    } catch (err) {
      setError(getErrorMessage(err, 'The change could not be saved.'))
    } finally {
      setBusy(false)
      setPending(null)
    }
  }

  const dialog = pending && describe(pending)

  return (
    <main className="flex-1 w-full max-w-6xl mx-auto px-4 py-10 text-slate-100 space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <Users className="w-8 h-8 text-sky-400" />
          <div>
            <h1 className="text-2xl font-semibold">User Management</h1>
            <p className="text-sm text-slate-400">Activate, deactivate and change roles (USER / ADMIN).</p>
          </div>
        </div>
        <Link to="/admin" className="text-sm text-sky-400 hover:text-sky-300">← Admin Dashboard</Link>
      </header>

      <FormAlert>{error}</FormAlert>
      <FormAlert tone="success">{notice}</FormAlert>
      {!users && !error && <p className="text-sm text-slate-400">Loading users…</p>}

      {users && (
        <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/80">
          <table className="w-full text-sm">
            <thead className="bg-slate-900 text-left text-xs uppercase tracking-wide text-slate-400">
              <tr>
                <th className="px-4 py-3">Name</th>
                <th className="px-4 py-3">Email</th>
                <th className="px-4 py-3">Role</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Created</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {users.map((user) => {
                const self = user.id === currentUser?.id
                return (
                  <tr key={user.id} className="hover:bg-slate-800/40">
                    <td className="px-4 py-3 font-medium">{user.name}{self && <span className="ml-2 text-xs text-slate-500">(you)</span>}</td>
                    <td className="px-4 py-3 text-slate-300 break-all">{user.email}</td>
                    <td className="px-4 py-3"><RoleBadge role={user.role} /></td>
                    <td className="px-4 py-3"><StatusBadge active={user.is_active} /></td>
                    <td className="px-4 py-3 text-slate-400 whitespace-nowrap">{new Date(user.created_at).toLocaleDateString()}</td>
                    <td className="px-4 py-3">
                      <div className="flex justify-end gap-2">
                        <button type="button" disabled={self} title={self ? 'You cannot change your own status' : undefined}
                                onClick={() => setPending({ user, type: 'status' })}
                                className={`${actionButton} ${user.is_active
                                  ? 'border-red-500/40 text-red-300 hover:bg-red-500/10'
                                  : 'border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/10'}`}>
                          {user.is_active ? 'Deactivate' : 'Activate'}
                        </button>
                        <button type="button" disabled={self} title={self ? 'You cannot change your own role' : undefined}
                                onClick={() => setPending({ user, type: 'role' })}
                                className={`${actionButton} border-slate-600 text-slate-200 hover:bg-slate-800`}>
                          {user.role === 'USER' ? 'Make ADMIN' : 'Make USER'}
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {dialog && (
        <ConfirmDialog title={dialog.title} message={dialog.message} confirmLabel={dialog.label}
                       danger={dialog.danger} busy={busy} onConfirm={confirm} onCancel={cancel} />
      )}
    </main>
  )
}
