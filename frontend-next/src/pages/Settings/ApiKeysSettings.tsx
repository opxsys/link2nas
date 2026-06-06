import { useState, useEffect, useCallback, useRef } from 'react'
import { Plus, Trash2, Ban, Loader2, AlertCircle, RefreshCw, CheckCircle2, X } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { listMyApiKeys, revokeApiKey, deleteApiKey } from '@/api/user-api-keys'
import { invalidateQbtWriteKeyStatus } from '@/lib/useQbtWriteKeyStatus'
import type { UserApiKey, CreatedApiKey } from '@/api/user-api-keys'
import { useI18n } from '@/i18n'
import CreateApiKeyModal from './CreateApiKeyModal'
import NewKeyReveal from './NewKeyReveal'

type ConfirmState = { keyId: string; keyName: string; action: 'revoke' | 'delete' } | null

const TH = 'px-4 py-2.5 text-left text-xs font-medium text-muted-foreground'
const TD = 'px-4 py-3 text-sm'

function ApiKeyStatusBadge({ active }: { active: boolean }) {
  const { t } = useI18n()
  return active
    ? <span className="inline-flex items-center rounded-full bg-green-50 px-2 py-0.5 text-xs font-medium text-green-700 border border-green-200 dark:bg-green-950 dark:text-green-400 dark:border-green-800">{t('badgeActive')}</span>
    : <span className="inline-flex items-center rounded-full bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground border border-border">{t('badgeRevoked')}</span>
}

export default function ApiKeysSettings() {
  const { t } = useI18n()
  const [keys, setKeys]           = useState<UserApiKey[] | null>(null)
  const [loading, setLoading]     = useState(true)
  const [fetchError, setFetchError] = useState<string | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [newKey, setNewKey]       = useState<CreatedApiKey | null>(null)
  const [confirm, setConfirm]     = useState<ConfirmState>(null)
  const [acting, setActing]       = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [actionSuccess, setActionSuccess] = useState<string | null>(null)
  const successTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const fetchKeys = useCallback(async () => {
    setLoading(true)
    setFetchError(null)
    try {
      setKeys(await listMyApiKeys())
    } catch (err) {
      setFetchError(err instanceof Error ? err.message : t('apiKeyLoadFailed'))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => { fetchKeys() }, [fetchKeys])

  useEffect(() => () => { if (successTimer.current) clearTimeout(successTimer.current) }, [])

  function showSuccess(msg: string) {
    if (successTimer.current) clearTimeout(successTimer.current)
    setActionSuccess(msg)
    successTimer.current = setTimeout(() => setActionSuccess(null), 4000)
  }

  function handleCreated(created: CreatedApiKey) {
    setCreateOpen(false)
    setNewKey(created)
    fetchKeys()
    invalidateQbtWriteKeyStatus()
  }

  async function handleConfirmedAction() {
    if (!confirm) return
    const { keyId, action } = confirm
    setActing(keyId)
    setActionError(null)
    setActionSuccess(null)
    setConfirm(null)
    try {
      if (action === 'revoke') {
        await revokeApiKey(keyId)
      } else {
        await deleteApiKey(keyId)
      }
      fetchKeys()
      invalidateQbtWriteKeyStatus()
      showSuccess(action === 'revoke' ? t('apiKeyRevoked') : t('apiKeyDeleted'))
    } catch (err) {
      setActionError(err instanceof Error ? err.message : t('apiKeyActionFailed'))
    } finally {
      setActing(null)
    }
  }

  return (
    <>
      <SectionCard
        title={t('sectionApiKeys')}
        description={t('apiKeysDesc')}
        actions={
          <Button variant="outline" size="sm" onClick={() => setCreateOpen(true)}>
            <Plus size={13} aria-hidden="true" /> {t('createKey')}
          </Button>
        }
        bodyClassName="p-0"
      >
        {newKey && (
          <div className="border-b border-border p-4">
            <NewKeyReveal
              keyName={newKey.name}
              rawKey={newKey.key}
              onDismiss={() => setNewKey(null)}
            />
          </div>
        )}

        {actionSuccess && (
          <div className="flex items-center justify-between gap-2 border-b border-border bg-emerald-50 px-4 py-3 text-xs text-emerald-700 dark:bg-emerald-950 dark:text-emerald-400">
            <span className="flex items-center gap-2">
              <CheckCircle2 size={13} aria-hidden="true" />
              {actionSuccess}
            </span>
            <button onClick={() => setActionSuccess(null)} className="shrink-0 opacity-60 hover:opacity-100" aria-label={t('dismiss')}>
              <X size={13} aria-hidden="true" />
            </button>
          </div>
        )}

        {actionError && (
          <div className="flex items-center justify-between gap-2 border-b border-border bg-red-50 px-4 py-3 text-xs text-red-700 dark:bg-red-950 dark:text-red-400">
            <span className="flex items-center gap-2">
              <AlertCircle size={13} aria-hidden="true" />
              {actionError}
            </span>
            <button onClick={() => setActionError(null)} className="shrink-0 opacity-60 hover:opacity-100" aria-label={t('dismiss')}>
              <X size={13} aria-hidden="true" />
            </button>
          </div>
        )}

        {loading && (
          <div className="flex items-center gap-2 px-4 py-8 text-muted-foreground">
            <Loader2 size={16} className="animate-spin" aria-hidden="true" />
            <span className="text-sm">{t('loadingApiKeys')}</span>
          </div>
        )}

        {fetchError && !loading && (
          <div className="flex items-center justify-between px-4 py-6">
            <span className="flex items-center gap-2 text-sm text-red-700 dark:text-red-400">
              <AlertCircle size={14} aria-hidden="true" /> {fetchError}
            </span>
            <Button variant="outline" size="sm" onClick={fetchKeys}>
              <RefreshCw size={13} className="mr-1.5" aria-hidden="true" /> {t('retry')}
            </Button>
          </div>
        )}

        {!loading && !fetchError && keys !== null && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  <th className={TH}>{t('colName')}</th>
                  <th className={TH}>{t('colPrefix')}</th>
                  <th className={TH}>{t('colScopes')}</th>
                  <th className={TH}>{t('colStatus')}</th>
                  <th className={`${TH} hidden sm:table-cell`}>{t('colCreated')}</th>
                  <th className={`${TH} hidden sm:table-cell`}>{t('colLastUsed')}</th>
                  <th className={TH}><span className="sr-only">{t('colActions')}</span></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {keys.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-4 py-8 text-center text-sm text-muted-foreground">
                      {t('noApiKeys')}
                    </td>
                  </tr>
                )}
                {keys.map(key => {
                  const isActing = acting === key.id
                  const isConfirming = confirm?.keyId === key.id

                  return (
                    <tr key={key.id} className="hover:bg-muted/20">
                      <td className={`${TD} font-medium text-foreground`}>{key.name}</td>
                      <td className={TD}>
                        <code className="rounded bg-muted px-2 py-0.5 text-xs text-muted-foreground">
                          {key.key_prefix}…
                        </code>
                      </td>
                      <td className={TD}>
                        <div className="flex flex-wrap gap-1">
                          {key.scopes.map(scope => (
                            <span key={scope} className="rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground">
                              {scope}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className={TD}><ApiKeyStatusBadge active={key.is_active} /></td>
                      <td className={`${TD} hidden text-muted-foreground sm:table-cell`}>
                        {key.created_at ? key.created_at.slice(0, 10) : '—'}
                      </td>
                      <td className={`${TD} hidden text-muted-foreground sm:table-cell`}>
                        {key.last_used_at ? key.last_used_at.slice(0, 10) : '—'}
                      </td>
                      <td className={`${TD} text-right`}>
                        {isActing ? (
                          <Loader2 size={14} className="ml-auto animate-spin text-muted-foreground" aria-hidden="true" />
                        ) : isConfirming ? (
                          <span className="flex items-center justify-end gap-2">
                            <span className="text-xs text-muted-foreground">
                              {confirm.action === 'revoke' ? t('confirmRevoke') : t('confirmDeleteKey')}
                            </span>
                            <Button size="sm" variant="destructive" onClick={handleConfirmedAction}>
                              {t('yes')}
                            </Button>
                            <Button size="sm" variant="outline" onClick={() => setConfirm(null)}>
                              {t('cancel')}
                            </Button>
                          </span>
                        ) : key.is_active ? (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-muted-foreground hover:text-amber-600 dark:hover:text-amber-400"
                            aria-label={`${t('btnRevoke')} ${key.name}`}
                            onClick={() => setConfirm({ keyId: key.id, keyName: key.name, action: 'revoke' })}
                          >
                            <Ban size={13} className="mr-1" aria-hidden="true" /> {t('btnRevoke')}
                          </Button>
                        ) : (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-destructive/60 hover:text-destructive"
                            aria-label={`${t('delete')} ${key.name}`}
                            onClick={() => setConfirm({ keyId: key.id, keyName: key.name, action: 'delete' })}
                          >
                            <Trash2 size={13} className="mr-1" aria-hidden="true" /> {t('delete')}
                          </Button>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}

        <p className="border-t border-border px-4 py-3 text-xs text-muted-foreground">
          {t('revokeNote')}
        </p>
      </SectionCard>

      {createOpen && (
        <CreateApiKeyModal
          onClose={() => setCreateOpen(false)}
          onCreated={handleCreated}
        />
      )}
    </>
  )
}
