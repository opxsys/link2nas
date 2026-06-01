import { useState, useEffect, useCallback } from 'react'
import { Loader2, AlertCircle, RefreshCw, CheckCircle2, XCircle, Copy, Plus } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { useSmtpStatus } from '@/lib/useSmtpStatus'
import {
  listUsers, enableUser, disableUser, deleteUser,
  verifyUserEmail, createInvitationLink, sendInvitationEmail,
  createResetLink, sendResetEmail,
} from '@/api/admin-users'
import type { RealUser, CreateUserResponse } from './admin.types'
import AdminUserRow from './AdminUserRow'
import AdminUserCreate from './AdminUserCreate'

type View = 'list' | 'create'
interface Banner { ok: boolean; message: string; url?: string; urlLabel?: string }

export default function AdminUsers() {
  const { smtpAvailable } = useSmtpStatus()
  const [view, setView] = useState<View>('list')
  const [users, setUsers] = useState<RealUser[]>([])
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState<string | null>(null)
  const [actingId, setActingId] = useState<string | null>(null)
  const [banner, setBanner] = useState<Banner | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setFetchError(null)
    try { setUsers(await listUsers()) }
    catch (err) { setFetchError(err instanceof Error ? err.message : 'Failed to load users.') }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  function updateUser(updated: RealUser) {
    setUsers((prev) => prev.map((u) => u.id === updated.id ? updated : u))
  }

  async function act(id: string, label: string, fn: () => Promise<void>) {
    setActingId(id)
    setBanner(null)
    try { await fn() }
    catch (err) { setBanner({ ok: false, message: err instanceof Error ? err.message : `${label} failed.` }) }
    finally { setActingId(null) }
  }

  function makeHandlers(user: RealUser) {
    return {
      onEnable: () => act(user.id, 'Enable', async () => updateUser(await enableUser(user.id))),
      onDisable: () => act(user.id, 'Disable', async () => updateUser(await disableUser(user.id))),
      onVerifyEmail: () => act(user.id, 'Verify email', async () => updateUser(await verifyUserEmail(user.id))),
      onDelete: async () => {
        if (!window.confirm(`Delete ${user.email}? This cannot be undone.`)) return
        await act(user.id, 'Delete', async () => {
          await deleteUser(user.id)
          setUsers((prev) => prev.filter((u) => u.id !== user.id))
        })
      },
      onGetInvitationLink: () => act(user.id, 'Invitation link', async () => {
        const r = await createInvitationLink(user.id)
        navigator.clipboard.writeText(r.invitation_url).catch(() => undefined)
        setBanner({ ok: true, message: 'Invitation link copied to clipboard.', url: r.invitation_url, urlLabel: 'Invitation URL' })
      }),
      onSendInvitationEmail: () => act(user.id, 'Send invitation', async () => {
        const r = await sendInvitationEmail(user.id)
        setBanner({ ok: r.ok, message: r.message ?? r.error ?? 'Done.' })
      }),
      onGetResetLink: () => act(user.id, 'Reset link', async () => {
        const r = await createResetLink(user.id)
        navigator.clipboard.writeText(r.reset_url).catch(() => undefined)
        setBanner({ ok: true, message: 'Password reset link copied to clipboard.', url: r.reset_url, urlLabel: 'Reset URL' })
      }),
      onSendResetEmail: () => act(user.id, 'Send reset', async () => {
        const r = await sendResetEmail(user.id)
        setBanner({ ok: r.ok, message: r.message ?? r.error ?? 'Done.' })
      }),
    }
  }

  function handleCreateSave(result: CreateUserResponse) {
    setUsers((prev) => [result, ...prev])
    setView('list')
    if (result.invitation?.invitation_url) {
      navigator.clipboard.writeText(result.invitation.invitation_url).catch(() => undefined)
      setBanner({ ok: true, message: 'User created. Invitation link copied to clipboard.', url: result.invitation.invitation_url, urlLabel: 'Invitation URL' })
    } else {
      setBanner({ ok: true, message: `User ${result.email} created.` })
    }
  }

  if (view === 'create') {
    return <AdminUserCreate onSave={handleCreateSave} onCancel={() => setView('list')} />
  }

  return (
    <SectionCard
      title="Users"
      description="All user accounts on this instance."
      actions={
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={load} disabled={loading}>
            <RefreshCw size={13} className="mr-1.5" aria-hidden="true" /> Refresh
          </Button>
          <Button size="sm" variant="outline" onClick={() => { setBanner(null); setView('create') }}>
            <Plus size={13} className="mr-1.5" aria-hidden="true" /> Create user
          </Button>
        </div>
      }
    >
      {banner && (
        <div className={`mb-4 flex flex-wrap items-start gap-3 rounded-md border px-3 py-2.5 text-sm ${banner.ok
          ? 'border-green-200 bg-green-50 text-green-700 dark:border-green-800 dark:bg-green-950 dark:text-green-400'
          : 'border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400'}`}>
          {banner.ok ? <CheckCircle2 size={15} className="mt-0.5 shrink-0" /> : <XCircle size={15} className="mt-0.5 shrink-0" />}
          <div className="min-w-0 flex-1">
            <p>{banner.message}</p>
            {banner.url && (
              <div className="mt-1 flex items-center gap-2">
                <span className="max-w-xs truncate font-mono text-xs opacity-75">{banner.url}</span>
                <Button size="sm" variant="outline" className="h-6 px-2 text-xs"
                  onClick={() => navigator.clipboard.writeText(banner.url!).catch(() => undefined)}>
                  <Copy size={11} className="mr-1" aria-hidden="true" /> Copy
                </Button>
              </div>
            )}
          </div>
          <button className="text-xs underline opacity-70 hover:opacity-100" onClick={() => setBanner(null)}>Dismiss</button>
        </div>
      )}

      {loading && (
        <div className="flex items-center gap-2 py-8 text-muted-foreground">
          <Loader2 size={18} className="animate-spin" aria-hidden="true" />
          <span className="text-sm">Loading users…</span>
        </div>
      )}
      {fetchError && (
        <div className="flex items-start gap-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
          <AlertCircle size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
          <div>
            <p className="font-medium">Failed to load users</p>
            <p className="mt-0.5 text-xs">{fetchError}</p>
            <Button size="sm" variant="outline" className="mt-3" onClick={load}>Retry</Button>
          </div>
        </div>
      )}
      {!loading && !fetchError && (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-border">
                {['User', 'Role', 'Status', 'Verified', 'Created', 'Last login', 'Actions'].map((h) => (
                  <th key={h} className="px-4 py-2 text-xs font-medium text-muted-foreground">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {users.length === 0 && (
                <tr><td colSpan={7} className="px-4 py-6 text-sm text-muted-foreground">No users found.</td></tr>
              )}
              {users.map((user) => (
                <AdminUserRow
                  key={user.id}
                  user={user}
                  isActing={actingId === user.id}
                  smtpAvailable={smtpAvailable}
                  handlers={makeHandlers(user)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {!smtpAvailable && (
        <p className="mt-3 text-xs text-amber-700 dark:text-amber-400">
          SMTP is not configured or disabled. Email sending is unavailable. Invitation and reset links can still be copied manually.
        </p>
      )}
    </SectionCard>
  )
}
