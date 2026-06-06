import { useState, useEffect, useCallback, useMemo } from 'react'
import { Loader2, AlertCircle, RefreshCw, CheckCircle2, XCircle, Copy, Plus, X } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { useSmtpStatus } from '@/lib/useSmtpStatus'
import { useI18n } from '@/i18n'
import {
  listUsers, enableUser, disableUser,
  verifyUserEmail, createInvitationLink, sendInvitationEmail,
  createResetLink, sendResetEmail,
} from '@/api/admin-users'
import type { RealUser, CreateUserResponse } from './admin.types'
import AdminUserRow from './AdminUserRow'
import AdminUserCreate from './AdminUserCreate'
import AdminUserEdit from './AdminUserEdit'
import AdminUserDeleteModal from './AdminUserDeleteModal'
import AdminUsersFilter, { type FilterChip } from './AdminUsersFilter'

type View = 'list' | 'create' | 'edit'
interface Banner { ok: boolean; message: string; url?: string }

export default function AdminUsers() {
  const { t } = useI18n()
  const { smtpAvailable } = useSmtpStatus()
  const [view, setView] = useState<View>('list')
  const [editingUser, setEditingUser] = useState<RealUser | null>(null)
  const [users, setUsers] = useState<RealUser[]>([])
  const [loading, setLoading] = useState(true)
  const [fetchError, setFetchError] = useState<string | null>(null)
  const [actingId, setActingId] = useState<string | null>(null)
  const [banner, setBanner] = useState<Banner | null>(null)
  const [deletePendingUser, setDeletePendingUser] = useState<RealUser | null>(null)
  const [search, setSearch] = useState('')
  const [filterChip, setFilterChip] = useState<FilterChip>('all')

  const load = useCallback(async () => {
    setLoading(true)
    setFetchError(null)
    try { setUsers(await listUsers()) }
    catch (err) { setFetchError(err instanceof Error ? err.message : t('adminLoadUsersFailed')) }
    finally { setLoading(false) }
  }, [])

  useEffect(() => { load() }, [load])

  const filtered = useMemo(() => {
    const now = new Date()
    const q = search.toLowerCase()
    return users
      .filter((u) => !q || u.email.toLowerCase().includes(q) || (u.display_name?.toLowerCase().includes(q) ?? false))
      .filter((u) => {
        switch (filterChip) {
          case 'active':     return u.is_active
          case 'disabled':   return !u.is_active
          case 'super_admin': return u.is_super_admin
          case 'unverified': return !u.email_verified
          case 'expired':    return Boolean(u.account_expires_at && new Date(u.account_expires_at) < now)
          default:           return true
        }
      })
  }, [users, search, filterChip])

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
      onEdit: () => { setBanner(null); setEditingUser(user); setView('edit') },
      onEnable: () => act(user.id, 'Enable', async () => updateUser(await enableUser(user.id))),
      onDisable: () => act(user.id, 'Disable', async () => updateUser(await disableUser(user.id))),
      onVerifyEmail: () => act(user.id, 'Verify email', async () => updateUser(await verifyUserEmail(user.id))),
      onDelete: () => { setBanner(null); setDeletePendingUser(user) },
      onGetInvitationLink: () => act(user.id, 'Invitation link', async () => {
        const r = await createInvitationLink(user.id)
        navigator.clipboard.writeText(r.invitation_url).catch(() => undefined)
        setBanner({ ok: true, message: t('adminInvLinkCopied'), url: r.invitation_url })
      }),
      onSendInvitationEmail: () => act(user.id, 'Send invitation', async () => {
        const r = await sendInvitationEmail(user.id)
        setBanner({ ok: r.ok, message: r.message ?? r.error ?? 'Done.' })
      }),
      onGetResetLink: () => act(user.id, 'Reset link', async () => {
        const r = await createResetLink(user.id)
        navigator.clipboard.writeText(r.reset_url).catch(() => undefined)
        setBanner({ ok: true, message: t('adminResetLinkCopied'), url: r.reset_url })
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
      setBanner({ ok: true, message: t('adminUserCreatedInvLink'), url: result.invitation.invitation_url })
    } else {
      setBanner({ ok: true, message: `User ${result.email} created.` })
    }
  }

  function handleEditSave(updated: RealUser) {
    updateUser(updated)
    setView('list')
    setEditingUser(null)
    setBanner({ ok: true, message: `User ${updated.email} updated.` })
  }

  function handleDeleted(userId: string) {
    setUsers((prev) => prev.filter((u) => u.id !== userId))
    setDeletePendingUser(null)
    setBanner({ ok: true, message: t('adminUserDeleted') })
  }

  if (view === 'create') return <AdminUserCreate onSave={handleCreateSave} onCancel={() => setView('list')} />
  if (view === 'edit' && editingUser) return <AdminUserEdit user={editingUser} onSave={handleEditSave} onCancel={() => { setView('list'); setEditingUser(null) }} />

  return (
    <>
    <SectionCard
      title={t('adminUsersTitle')}
      description={t('adminUsersDesc')}
      actions={
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={load} disabled={loading}>
            {loading
              ? <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />
              : <RefreshCw size={13} className="mr-1.5" aria-hidden="true" />}
            {t('refresh')}
          </Button>
          <Button size="sm" variant="outline" onClick={() => { setBanner(null); setView('create') }}>
            <Plus size={13} className="mr-1.5" aria-hidden="true" /> {t('adminCreateUser')}
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
                  <Copy size={11} className="mr-1" aria-hidden="true" /> {t('copy')}
                </Button>
              </div>
            )}
          </div>
          <button
            className="ml-1 shrink-0 rounded hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            onClick={() => setBanner(null)}
            aria-label={t('dismiss')}
          >
            <X size={13} aria-hidden="true" />
          </button>
        </div>
      )}

      <AdminUsersFilter search={search} filter={filterChip} onSearch={setSearch} onFilter={setFilterChip} />

      {loading && (
        <div className="flex items-center gap-2 py-8 text-muted-foreground">
          <Loader2 size={18} className="animate-spin" aria-hidden="true" />
          <span className="text-sm">{t('adminLoadingUsers')}</span>
        </div>
      )}
      {fetchError && (
        <div className="flex items-start gap-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
          <AlertCircle size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
          <div>
            <p className="font-medium">{t('adminLoadUsersFailed')}</p>
            <p className="mt-0.5 text-xs">{fetchError}</p>
            <Button size="sm" variant="outline" className="mt-3" onClick={load}>{t('retry')}</Button>
          </div>
        </div>
      )}
      {!loading && !fetchError && (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-border">
                {[t('adminColUser'), t('adminColRole'), t('colStatus'), t('verified'), t('colCreated'), t('adminColLastLogin'), t('colActions')].map((h) => (
                  <th key={h} className="px-4 py-2 text-xs font-medium text-muted-foreground">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 && (
                <tr><td colSpan={7} className="px-4 py-6 text-sm text-muted-foreground">
                  {users.length === 0 ? t('adminNoUsersFound') : t('adminNoUsersMatch')}
                </td></tr>
              )}
              {filtered.map((user) => (
                <AdminUserRow key={user.id} user={user} isActing={actingId === user.id}
                  smtpAvailable={smtpAvailable} handlers={makeHandlers(user)} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {!smtpAvailable && (
        <p className="mt-3 text-xs text-amber-700 dark:text-amber-400">
          {t('adminSmtpEmailWarning')}
        </p>
      )}
    </SectionCard>

    {deletePendingUser && (
      <AdminUserDeleteModal
        user={deletePendingUser}
        onDeleted={handleDeleted}
        onClose={() => setDeletePendingUser(null)}
      />
    )}
    </>
  )
}
