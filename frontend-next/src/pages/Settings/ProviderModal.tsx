import { useState, useEffect } from 'react'
import { X, Loader2, KeyRound } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { saveProviderConfig } from '@/api/provider-configs'
import { ApiError } from '@/api/client'
import type { ProviderConfig } from '@/api/provider-configs'
import { useI18n } from '@/i18n'
import { PROVIDER_TYPES } from '@/lib/provider-types'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'
const SELECT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'

interface Props {
  initial: ProviderConfig | null  // null = create, set = edit
  onClose: () => void
  onSaved: () => void
}

export default function ProviderModal({ initial, onClose, onSaved }: Props) {
  const { t } = useI18n()
  const isEdit = initial !== null

  const [name,         setName]         = useState(initial?.name          ?? '')
  const [providerType, setProviderType] = useState(initial?.provider_type ?? 'realdebrid')
  const [apiKey,       setApiKey]       = useState('')
  const [isEnabled,    setIsEnabled]    = useState(initial?.is_enabled    ?? true)
  const [isDefault,    setIsDefault]    = useState(initial?.is_default    ?? false)
  const [saving,       setSaving]       = useState(false)
  const [error,        setError]        = useState<string | null>(null)

  useEffect(() => {
    setName(initial?.name          ?? '')
    setProviderType(initial?.provider_type ?? 'realdebrid')
    setApiKey('')
    setIsEnabled(initial?.is_enabled ?? true)
    setIsDefault(initial?.is_default ?? false)
    setError(null)
  }, [initial])

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) { setError(t('nameRequired')); return }
    if (!isEdit && !apiKey.trim()) { setError(t('provApiKeyRequired')); return }

    setSaving(true)
    setError(null)
    try {
      await saveProviderConfig({
        provider_config_id: initial?.id,
        provider_type: providerType,
        name: name.trim(),
        api_key: apiKey.trim() || undefined,
        is_enabled: isEnabled,
        is_default: isDefault,
      })
      onSaved()
      onClose()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('providerSaveFailed'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      role="dialog"
      aria-modal="true"
      aria-label={isEdit ? t('editProvider') : t('addProvider')}
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}
    >
      <div className="w-full max-w-md rounded-lg border border-border bg-card shadow-lg">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <h2 className="text-sm font-semibold text-foreground">
            {isEdit ? `${t('editModalPre')} ${initial.name}` : t('addProvider')}
          </h2>
          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={onClose} aria-label={t('close')}>
            <X size={14} aria-hidden="true" />
          </Button>
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4 p-5">
          <div>
            <label htmlFor="prov-name" className={LABEL}>{t('colName')}</label>
            <input id="prov-name" type="text" value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Real-Debrid personal" className={INPUT} />
          </div>

          <div>
            <label htmlFor="prov-type" className={LABEL}>{t('labelProviderType')}</label>
            <select id="prov-type" value={providerType}
              onChange={(e) => setProviderType(e.target.value)}
              disabled={isEdit} className={SELECT}>
              {PROVIDER_TYPES.map(pt => (
                <option key={pt.value} value={pt.value}>{pt.label}</option>
              ))}
            </select>
            {isEdit && (
              <p className="mt-1 text-xs text-muted-foreground">{t('provTypeLocked')}</p>
            )}
          </div>

          <div>
            <label htmlFor="prov-apikey" className={LABEL}>
              {isEdit ? t('labelApiKeyEdit') : t('labelApiKey')}
            </label>
            {isEdit && initial.has_api_key && !apiKey && (
              <p className="mb-1.5 flex items-center gap-1 text-xs text-muted-foreground">
                <KeyRound size={11} aria-hidden="true" /> {t('apiKeyAlreadySet')}
              </p>
            )}
            <input id="prov-apikey" type="password" value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={isEdit ? '••••••••  (unchanged)' : 'Paste your API key'}
              className={INPUT} autoComplete="new-password" />
          </div>

          <div className="flex gap-6">
            <label className="flex cursor-pointer items-center gap-2 text-sm text-foreground">
              <input type="checkbox" checked={isEnabled}
                onChange={(e) => setIsEnabled(e.target.checked)}
                className="h-4 w-4 rounded border-input accent-primary" />
              {t('labelEnabled')}
            </label>
            <label className="flex cursor-pointer items-center gap-2 text-sm text-foreground">
              <input type="checkbox" checked={isDefault}
                onChange={(e) => setIsDefault(e.target.checked)}
                className="h-4 w-4 rounded border-input accent-primary" />
              {t('badgeDefault')}
            </label>
          </div>

          {error && <p className="text-sm text-destructive">{error}</p>}

          <div className="flex items-center justify-end gap-2 border-t border-border pt-3">
            <Button type="button" variant="outline" size="sm" onClick={onClose} disabled={saving}>
              {t('cancel')}
            </Button>
            <Button type="submit" size="sm" disabled={saving}>
              {saving && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
              {isEdit ? t('saveChanges') : t('addProvider')}
            </Button>
          </div>
        </form>
      </div>
    </div>
  )
}
