import { useState } from 'react'
import { X, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { ApiError } from '@/api/client'
import { createAdminOidcProvider, updateAdminOidcProvider } from '@/api/admin-oidc-providers'
import { useI18n } from '@/i18n'
import type { AdminOidcProvider, OidcProviderPayload } from './admin.types'

const LABEL = 'mb-1 block text-xs font-medium text-foreground'
const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const HINT = 'mt-1 text-xs text-muted-foreground'

interface Props {
  provider: AdminOidcProvider | null
  onSaved: (p: AdminOidcProvider) => void
  onClose: () => void
}

function domainsToString(arr: string[]): string { return arr.join(', ') }
function stringToDomains(s: string): string[] {
  return s.split(',').map(d => d.trim().toLowerCase()).filter(Boolean)
}

export default function AdminSsoProviderForm({ provider, onSaved, onClose }: Props) {
  const { t } = useI18n()
  const isEdit = provider !== null

  const [name, setName]       = useState(provider?.name ?? '')
  const [slug, setSlug]       = useState(provider?.slug ?? '')
  const [issuer, setIssuer]   = useState(provider?.issuer ?? '')
  const [clientId, setClientId] = useState(provider?.client_id ?? '')
  const [secret, setSecret]   = useState('')
  const [scopes, setScopes]   = useState(provider?.scopes ?? 'openid email profile')
  const [buttonLabel, setButtonLabel] = useState(provider?.button_label ?? '')
  const [autoCreate, setAutoCreate]   = useState(provider?.auto_create_users ?? false)
  const [domains, setDomains] = useState(isEdit ? domainsToString(provider.allowed_domains) : '')
  const [stateTtl, setStateTtl]     = useState(provider?.state_ttl_seconds ?? 600)
  const [exchangeTtl, setExchangeTtl] = useState(provider?.exchange_code_ttl_seconds ?? 60)
  const [sortOrder, setSortOrder]   = useState(provider?.sort_order ?? 0)
  const [enabled, setEnabled] = useState(provider?.enabled ?? true)

  const [saving, setSaving] = useState(false)
  const [error, setError]   = useState<string | null>(null)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setSaving(true)
    try {
      const payload: Partial<OidcProviderPayload> = {
        name: name.trim(),
        enabled,
        issuer: issuer.trim(),
        client_id: clientId.trim(),
        scopes: scopes.trim(),
        button_label: buttonLabel.trim(),
        auto_create_users: autoCreate,
        allowed_domains: stringToDomains(domains),
        state_ttl_seconds: stateTtl,
        exchange_code_ttl_seconds: exchangeTtl,
        sort_order: sortOrder,
      }
      if (!isEdit) {
        payload.slug = slug.trim()
      }
      if (secret.trim()) {
        payload.client_secret = secret.trim()
      }

      const saved = isEdit
        ? await updateAdminOidcProvider(provider.id, payload)
        : await createAdminOidcProvider(payload as OidcProviderPayload)

      onSaved(saved)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('adminSsoSaveFailed'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/50 p-4"
      role="dialog"
      aria-modal="true"
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}
    >
      <div className="my-8 w-full max-w-lg rounded-lg border border-border bg-card shadow-lg">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <h2 className="text-sm font-semibold text-foreground">
            {isEdit ? t('adminSsoEditTitle') : t('adminSsoCreateTitle')}
          </h2>
          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={onClose} aria-label={t('close')}>
            <X size={14} aria-hidden="true" />
          </Button>
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4 p-5">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className={LABEL}>{t('adminSsoProviderName')}</label>
              <input className={INPUT} value={name} onChange={e => setName(e.target.value)} disabled={saving} required />
            </div>
            <div>
              <label className={LABEL}>{t('adminSsoSlug')}</label>
              <input
                className={INPUT}
                value={slug}
                onChange={e => setSlug(e.target.value)}
                disabled={saving || isEdit}
                placeholder={isEdit ? provider.slug : 'keycloak'}
                required={!isEdit}
              />
              {!isEdit && <p className={HINT}>{t('adminSsoSlugHint')}</p>}
            </div>
          </div>

          <div>
            <label className={LABEL}>{t('adminSsoIssuer')}</label>
            <input className={INPUT} value={issuer} onChange={e => setIssuer(e.target.value)} disabled={saving} placeholder="https://idp.example.com/realm/myrealm" required />
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className={LABEL}>{t('adminSsoClientId')}</label>
              <input className={INPUT} value={clientId} onChange={e => setClientId(e.target.value)} disabled={saving} required />
            </div>
            <div>
              <label className={LABEL}>{t('adminSsoClientSecret')}</label>
              <input
                className={INPUT}
                type="password"
                autoComplete="new-password"
                value={secret}
                onChange={e => setSecret(e.target.value)}
                disabled={saving}
                placeholder={isEdit && provider.has_client_secret ? t('adminSsoSecretConfigured') : ''}
              />
              {!isEdit && <p className={HINT}>{t('adminSsoSecretHint')}</p>}
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label className={LABEL}>{t('adminSsoScopes')}</label>
              <input className={INPUT} value={scopes} onChange={e => setScopes(e.target.value)} disabled={saving} />
            </div>
            <div>
              <label className={LABEL}>{t('adminSsoButtonLabel')}</label>
              <input className={INPUT} value={buttonLabel} onChange={e => setButtonLabel(e.target.value)} disabled={saving} placeholder="Sign in with Keycloak" />
            </div>
          </div>

          <div>
            <label className={LABEL}>{t('adminSsoAllowedDomains')}</label>
            <input className={INPUT} value={domains} onChange={e => setDomains(e.target.value)} disabled={saving} placeholder="example.com, corp.example.com" />
            <p className={HINT}>{t('adminSsoAllowedDomainsHint')}</p>
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className={LABEL}>{t('adminSsoStateTtl')}</label>
              <input className={INPUT} type="number" min={30} value={stateTtl} onChange={e => setStateTtl(Number(e.target.value))} disabled={saving} />
            </div>
            <div>
              <label className={LABEL}>{t('adminSsoExchangeTtl')}</label>
              <input className={INPUT} type="number" min={10} value={exchangeTtl} onChange={e => setExchangeTtl(Number(e.target.value))} disabled={saving} />
            </div>
            <div>
              <label className={LABEL}>{t('adminSsoSortOrder')}</label>
              <input className={INPUT} type="number" value={sortOrder} onChange={e => setSortOrder(Number(e.target.value))} disabled={saving} />
            </div>
          </div>

          <div className="flex items-center gap-3">
            <label className="flex cursor-pointer items-center gap-2 text-sm text-foreground">
              <input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} disabled={saving} className="h-4 w-4 rounded border-input" />
              {t('adminSsoEnabled')}
            </label>
            <label className="flex cursor-pointer items-center gap-2 text-sm text-foreground">
              <input type="checkbox" checked={autoCreate} onChange={e => setAutoCreate(e.target.checked)} disabled={saving} className="h-4 w-4 rounded border-input" />
              {t('adminSsoAutoCreateUsers')}
            </label>
          </div>

          {error && (
            <p className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{error}</p>
          )}

          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <Button type="button" variant="outline" size="sm" onClick={onClose} disabled={saving}>
              {t('adminSsoCancel')}
            </Button>
            <Button type="submit" size="sm" disabled={saving}>
              {saving && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
              {t('adminSsoSave')}
            </Button>
          </div>
        </form>
      </div>
    </div>
  )
}
