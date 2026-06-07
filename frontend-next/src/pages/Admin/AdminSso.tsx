import { useState, useEffect, useCallback } from 'react'
import { Plus, X, Loader2, Trash2 } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { ApiError } from '@/api/client'
import {
  listAdminOidcProviders,
  deleteAdminOidcProvider,
  testAdminOidcProviderDiscovery,
} from '@/api/admin-oidc-providers'
import { useI18n } from '@/i18n'
import AdminSsoProviderRow from './AdminSsoProviderRow'
import AdminSsoProviderForm from './AdminSsoProviderForm'
import type { AdminOidcProvider } from './admin.types'

interface DiscoveryResult {
  ok: boolean
  error?: string
}

export default function AdminSso() {
  const { t } = useI18n()

  const [providers, setProviders]     = useState<AdminOidcProvider[]>([])
  const [loading, setLoading]         = useState(true)
  const [loadError, setLoadError]     = useState<string | null>(null)

  const [formOpen, setFormOpen]       = useState(false)
  const [editing, setEditing]         = useState<AdminOidcProvider | null>(null)

  const [deleteTarget, setDeleteTarget] = useState<AdminOidcProvider | null>(null)
  const [deletePending, setDeletePending] = useState(false)
  const [deleteError, setDeleteError] = useState<string | null>(null)

  const [testPending, setTestPending] = useState<Record<string, boolean>>({})
  const [testResults, setTestResults] = useState<Record<string, DiscoveryResult>>({})

  const load = useCallback(async () => {
    setLoading(true)
    setLoadError(null)
    try {
      setProviders(await listAdminOidcProviders())
    } catch {
      setLoadError(t('adminSsoLoadFailed'))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => { load() }, [load])

  function openCreate() { setEditing(null); setFormOpen(true) }
  function openEdit(p: AdminOidcProvider) { setEditing(p); setFormOpen(true) }
  function closeForm() { setFormOpen(false); setEditing(null) }

  function handleSaved(p: AdminOidcProvider) {
    closeForm()
    load()
  }

  function openDelete(p: AdminOidcProvider) {
    setDeleteTarget(p)
    setDeleteError(null)
  }

  async function handleDelete() {
    if (!deleteTarget) return
    setDeletePending(true)
    setDeleteError(null)
    try {
      await deleteAdminOidcProvider(deleteTarget.id)
      setDeleteTarget(null)
      load()
    } catch (err) {
      const msg = err instanceof ApiError && err.status === 409
        ? t('adminSsoDeleteInUse')
        : (err instanceof ApiError ? err.message : t('adminSsoDeleteFailed'))
      setDeleteError(msg)
    } finally {
      setDeletePending(false)
    }
  }

  async function handleTest(p: AdminOidcProvider) {
    setTestPending(prev => ({ ...prev, [p.id]: true }))
    try {
      const result = await testAdminOidcProviderDiscovery(p.id)
      setTestResults(prev => ({ ...prev, [p.id]: result }))
    } catch {
      setTestResults(prev => ({ ...prev, [p.id]: { ok: false, error: t('adminSsoDiscoveryFailed') } }))
    } finally {
      setTestPending(prev => ({ ...prev, [p.id]: false }))
    }
  }

  return (
    <>
      <SectionCard
        title={t('adminSsoTitle')}
        description={t('adminSsoSubtitle')}
        actions={
          <Button type="button" size="sm" onClick={openCreate}>
            <Plus size={13} className="mr-1.5" aria-hidden="true" />
            {t('adminSsoAddProvider')}
          </Button>
        }
      >
        {loading ? (
          <div className="flex items-center gap-2 py-4 text-sm text-muted-foreground">
            <Loader2 size={14} className="animate-spin" aria-hidden="true" />
            {t('adminSsoLoadingProviders')}
          </div>
        ) : loadError ? (
          <div className="flex items-center justify-between py-2">
            <p className="text-sm text-destructive">{loadError}</p>
            <Button variant="outline" size="sm" onClick={load}>{t('retry')}</Button>
          </div>
        ) : providers.length === 0 ? (
          <p className="py-2 text-sm text-muted-foreground">{t('adminSsoNoProviders')}</p>
        ) : (
          <div className="flex flex-col gap-2">
            {providers.map((p) => (
              <AdminSsoProviderRow
                key={p.id}
                provider={p}
                testResult={testResults[p.id] ?? null}
                testPending={testPending[p.id] ?? false}
                onEdit={() => openEdit(p)}
                onDelete={() => openDelete(p)}
                onTest={() => handleTest(p)}
              />
            ))}
          </div>
        )}
      </SectionCard>

      {formOpen && (
        <AdminSsoProviderForm
          provider={editing}
          onSaved={handleSaved}
          onClose={closeForm}
        />
      )}

      {deleteTarget && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
          role="dialog"
          aria-modal="true"
          onMouseDown={(e) => { if (e.target === e.currentTarget) setDeleteTarget(null) }}
        >
          <div className="w-full max-w-sm rounded-lg border border-border bg-card shadow-lg">
            <div className="flex items-center justify-between border-b border-border px-5 py-4">
              <h2 className="text-sm font-semibold text-foreground">{t('adminSsoDeleteConfirmTitle')}</h2>
              <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setDeleteTarget(null)} aria-label={t('close')}>
                <X size={14} aria-hidden="true" />
              </Button>
            </div>
            <div className="p-5">
              <p className="text-sm text-foreground">
                {t('adminSsoDeleteConfirmBody')}{' '}
                <span className="font-semibold">{deleteTarget.name}</span>?
              </p>
              {deleteError && (
                <p className="mt-3 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
                  {deleteError}
                </p>
              )}
              <div className="mt-4 flex justify-end gap-2">
                <Button type="button" variant="outline" size="sm" onClick={() => setDeleteTarget(null)} disabled={deletePending}>
                  {t('adminSsoCancel')}
                </Button>
                <Button type="button" variant="destructive" size="sm" onClick={handleDelete} disabled={deletePending}>
                  {deletePending && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
                  <Trash2 size={13} className="mr-1.5" aria-hidden="true" />
                  {t('delete')}
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
