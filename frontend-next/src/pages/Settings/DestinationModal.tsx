import { useState, useEffect } from 'react'
import { X, Loader2, Info } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { saveDestinationConfig } from '@/api/destination-configs'
import { ApiError } from '@/api/client'
import type { DestinationConfig } from '@/api/destination-configs'
import { getMe } from '@/api/me'
import { useAppInfo } from '@/lib/useAppInfo'
import { useI18n } from '@/i18n'
import { DESTINATION_TYPES as ALL_DEST_TYPES } from '@/lib/destination-types'

const INPUT  = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const LABEL  = 'mb-1.5 block text-xs font-medium text-foreground'
const SELECT = INPUT

interface Props {
  initial: DestinationConfig | null  // null = create, set = edit
  onClose: () => void
  onSaved: () => void
}

export default function DestinationModal({ initial, onClose, onSaved }: Props) {
  const { t } = useI18n()
  const isEdit = initial !== null
  const { appInfo } = useAppInfo()
  const appName = appInfo.app_name || 'Link2NAS'

  const [name,            setName]            = useState(initial?.name                          ?? '')
  const [destType,        setDestType]        = useState(initial?.destination_type              ?? 'synology')
  const [synologyUrl,     setSynologyUrl]     = useState(initial?.config.synology_url           ?? '')
  const [username,        setUsername]        = useState(initial?.config.username               ?? '')
  const [password,        setPassword]        = useState('')
  const [verifySSL,       setVerifySSL]       = useState(initial?.config.verify_ssl             !== false)
  const [destinationBase, setDestinationBase] = useState(initial?.config.destination_base       ?? '')
  const [basePath,        setBasePath]        = useState(initial?.config.base_path              ?? '')
  const [isEnabled,       setIsEnabled]       = useState(initial?.is_enabled                    ?? true)
  const [isDefault,       setIsDefault]       = useState(initial?.is_default                    ?? false)
  const [saving,          setSaving]          = useState(false)
  const [error,           setError]           = useState<string | null>(null)
  const [canUseLocal,     setCanUseLocal]     = useState(false)

  useEffect(() => {
    getMe().then(me => setCanUseLocal(me.can_use_local_space)).catch(() => {/* keep false */})
  }, [])

  const availableTypes = ALL_DEST_TYPES.filter(dt => {
    if (dt.value !== 'local') return true
    return canUseLocal || (isEdit && initial?.destination_type === 'local')
  })

  useEffect(() => {
    setName(initial?.name ?? '')
    setDestType(initial?.destination_type ?? 'synology')
    setSynologyUrl(initial?.config.synology_url ?? '')
    setUsername(initial?.config.username ?? '')
    setPassword('')
    setVerifySSL(initial?.config.verify_ssl !== false)
    setDestinationBase(initial?.config.destination_base ?? '')
    setBasePath(initial?.config.base_path ?? '')
    setIsEnabled(initial?.is_enabled ?? true)
    setIsDefault(initial?.is_default ?? false)
    setError(null)
  }, [initial])

  function buildConfigJson(): string {
    if (destType === 'local') {
      return JSON.stringify({ base_path: basePath.trim() || 'downloads' })
    }
    const cfg: Record<string, unknown> = {
      synology_url: synologyUrl.trim(),
      username:     username.trim(),
      verify_ssl:   verifySSL,
    }
    if (destinationBase.trim()) cfg.destination_base = destinationBase.trim()
    if (password.trim())        cfg.password         = password.trim()
    return JSON.stringify(cfg)
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) { setError(t('nameRequired')); return }
    if (destType === 'synology') {
      if (!synologyUrl.trim()) { setError(t('destUrlRequired')); return }
      if (!username.trim())    { setError(t('destUsernameRequired')); return }
      if (!isEdit && !password.trim()) { setError(t('destPasswordRequired')); return }
    }
    setSaving(true)
    setError(null)
    try {
      await saveDestinationConfig({
        destination_config_id: initial?.id,
        destination_type:      destType,
        name:                  name.trim(),
        config_json:           buildConfigJson(),
        is_enabled:            isEnabled,
        is_default:            isDefault,
      })
      onSaved()
      onClose()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('destinationSaveFailed'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      role="dialog" aria-modal="true"
      aria-label={isEdit ? t('editDestination') : t('addDestination')}
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}
    >
      <div className="max-h-[90vh] w-full max-w-md overflow-y-auto rounded-lg border border-border bg-card shadow-lg">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <h2 className="text-sm font-semibold text-foreground">
            {isEdit ? `${t('editModalPre')} ${initial.name}` : t('addDestination')}
          </h2>
          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={onClose} aria-label={t('close')}>
            <X size={14} aria-hidden="true" />
          </Button>
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4 p-5">
          <div>
            <label htmlFor="dest-name" className={LABEL}>{t('colName')}</label>
            <input id="dest-name" type="text" value={name} onChange={(e) => setName(e.target.value)}
              placeholder="e.g. NAS Maison" className={INPUT} />
          </div>

          <div>
            <label htmlFor="dest-type" className={LABEL}>{t('labelDestinationType')}</label>
            <select id="dest-type" value={destType} onChange={(e) => setDestType(e.target.value)}
              disabled={isEdit} className={SELECT}>
              {availableTypes.map(dt => <option key={dt.value} value={dt.value}>{dt.label}</option>)}
            </select>
            {isEdit && (
              <p className="mt-1 text-xs text-muted-foreground">{t('destTypeLocked')}</p>
            )}
          </div>

          {destType === 'synology' && (
            <>
              <div>
                <label htmlFor="dest-url" className={LABEL}>{t('labelSynologyUrl')}</label>
                <input id="dest-url" type="text" value={synologyUrl}
                  onChange={(e) => setSynologyUrl(e.target.value)}
                  placeholder="http://nas.local:5000" className={INPUT} />
              </div>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div>
                  <label htmlFor="dest-user" className={LABEL}>{t('labelUsername')}</label>
                  <input id="dest-user" type="text" value={username}
                    onChange={(e) => setUsername(e.target.value)} autoComplete="off" className={INPUT} />
                </div>
                <div>
                  <label htmlFor="dest-pw" className={LABEL}>
                    {isEdit ? t('labelPasswordOptional') : t('labelPassword')}
                  </label>
                  <input id="dest-pw" type="password" value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={isEdit ? '••••••••  (unchanged)' : ''}
                    autoComplete="new-password" className={INPUT} />
                </div>
              </div>
              {isEdit && (
                <div className="flex items-start gap-2 rounded-md bg-muted/50 p-2 text-xs text-muted-foreground">
                  <Info size={12} className="mt-0.5 shrink-0" aria-hidden="true" />
                  {t('leaveBlankKeepPassword')}
                </div>
              )}
              <div>
                <label htmlFor="dest-base" className={LABEL}>{t('labelDestFolder')}</label>
                <input id="dest-base" type="text" value={destinationBase}
                  onChange={(e) => setDestinationBase(e.target.value)}
                  placeholder="downloads" className={INPUT} />
                <p className="mt-1 text-xs text-muted-foreground">
                  {t('destFolderHintPre')} {appName} {t('destFolderHintPost')}
                </p>
              </div>
              <label className="flex cursor-pointer items-center gap-2 text-sm text-foreground">
                <input type="checkbox" checked={verifySSL} onChange={(e) => setVerifySSL(e.target.checked)}
                  className="h-4 w-4 rounded border-input accent-primary" />
                {t('verifySSL')}
              </label>
            </>
          )}

          {destType === 'local' && (
            <div>
              <label htmlFor="dest-path" className={LABEL}>{t('labelBasePath')}</label>
              <input id="dest-path" type="text" value={basePath}
                onChange={(e) => setBasePath(e.target.value)} placeholder="downloads" className={INPUT} />
              <p className="mt-1 text-xs text-muted-foreground">{t('destPathHint')}</p>
            </div>
          )}

          <div className="flex gap-6">
            <label className="flex cursor-pointer items-center gap-2 text-sm text-foreground">
              <input type="checkbox" checked={isEnabled} onChange={(e) => setIsEnabled(e.target.checked)}
                className="h-4 w-4 rounded border-input accent-primary" />
              {t('labelEnabled')}
            </label>
            <label className="flex cursor-pointer items-center gap-2 text-sm text-foreground">
              <input type="checkbox" checked={isDefault} onChange={(e) => setIsDefault(e.target.checked)}
                className="h-4 w-4 rounded border-input accent-primary" />
              {t('badgeDefault')}
            </label>
          </div>

          {error && <p className="text-sm text-destructive">{error}</p>}

          <div className="flex items-center justify-end gap-2 border-t border-border pt-3">
            <Button type="button" variant="outline" size="sm" onClick={onClose} disabled={saving}>{t('cancel')}</Button>
            <Button type="submit" size="sm" disabled={saving}>
              {saving && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
              {isEdit ? t('saveChanges') : t('addDestination')}
            </Button>
          </div>
        </form>
      </div>
    </div>
  )
}
