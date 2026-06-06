import { useState } from 'react'
import { X, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { createApiKey } from '@/api/user-api-keys'
import type { CreatedApiKey } from '@/api/user-api-keys'
import { useI18n } from '@/i18n'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'

interface Props {
  onClose: () => void
  onCreated: (created: CreatedApiKey) => void
}

export default function CreateApiKeyModal({ onClose, onCreated }: Props) {
  const { t } = useI18n()

  const SCOPES = [
    { value: 'qbittorrent:write', label: 'qBittorrent / Prowlarr', description: t('qbtScopeDesc') },
  ]

  const [name, setName]     = useState('')
  const [scopes, setScopes] = useState<string[]>(['qbittorrent:write'])
  const [saving, setSaving] = useState(false)
  const [error, setError]   = useState<string | null>(null)

  function toggleScope(scope: string) {
    setScopes(prev =>
      prev.includes(scope) ? prev.filter(s => s !== scope) : [...prev, scope]
    )
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) { setError(t('nameRequired')); return }
    if (scopes.length === 0) { setError(t('apiKeyScopeRequired')); return }

    setSaving(true)
    setError(null)
    try {
      const created = await createApiKey({ name: name.trim(), scopes })
      onCreated(created)
    } catch (err) {
      setError(err instanceof Error ? err.message : t('apiKeyCreationFailed'))
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4" role="dialog" aria-modal="true" aria-labelledby="create-key-title">
      <div className="w-full max-w-md rounded-lg border border-border bg-background shadow-xl">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <h2 id="create-key-title" className="text-sm font-semibold text-foreground">{t('newApiKeyTitle')}</h2>
          <button type="button" onClick={onClose} aria-label={t('close')} className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground">
            <X size={16} aria-hidden="true" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col gap-5 p-5">
          <div>
            <label htmlFor="key-name" className="mb-1.5 block text-xs font-medium text-foreground">{t('colName')}</label>
            <input
              id="key-name"
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="e.g. Prowlarr integration"
              maxLength={120}
              disabled={saving}
              className={INPUT}
              autoFocus
            />
          </div>

          <div>
            <p className="mb-2 text-xs font-medium text-foreground">{t('labelScopes')}</p>
            <div className="flex flex-col gap-2.5">
              {SCOPES.map(s => (
                <label key={s.value} className="flex cursor-pointer items-start gap-3">
                  <input
                    type="checkbox"
                    checked={scopes.includes(s.value)}
                    onChange={() => toggleScope(s.value)}
                    disabled={saving}
                    className="mt-0.5 h-4 w-4 rounded border-input accent-primary disabled:opacity-50"
                  />
                  <div>
                    <p className="text-sm font-medium text-foreground">{s.label}</p>
                    <p className="text-xs text-muted-foreground">{s.description}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {error && (
            <p className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
              {error}
            </p>
          )}

          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <Button type="button" variant="outline" size="sm" onClick={onClose} disabled={saving}>{t('cancel')}</Button>
            <Button type="submit" size="sm" disabled={saving}>
              {saving && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
              {t('createKey')}
            </Button>
          </div>
        </form>
      </div>
    </div>
  )
}
