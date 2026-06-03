import { useState, useId } from 'react'
import { X, Loader2, AlertTriangle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { createNotificationConfig, updateNotificationConfig } from '@/api/notifications'
import { ApiError } from '@/api/client'
import type { NotificationConfig } from '@/pages/Notifications/notifications.types'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'

type Channel = 'email' | 'gotify' | 'webhook'

interface Props {
  editing: NotificationConfig | null
  smtpEnabled: boolean | null
  onClose: () => void
  onSaved: (cfg: NotificationConfig) => void
}

export default function NotifChannelModal({ editing, smtpEnabled, onClose, onSaved }: Props) {
  const isEdit = editing !== null
  const uid = useId()

  const [name, setName] = useState(editing?.name ?? '')
  const [channel, setChannel] = useState<Channel>((editing?.channel as Channel) ?? 'email')
  const [isEnabled, setIsEnabled] = useState(editing?.is_enabled ?? true)
  const [isDefault, setIsDefault] = useState(editing?.is_default ?? false)
  // email
  const [toEmail, setToEmail] = useState(editing?.config.to_email ?? '')
  // gotify — token never pre-filled (backend only returns has_token)
  const [gotifyUrl, setGotifyUrl] = useState(editing?.config.server_url ?? '')
  const [gotifyToken, setGotifyToken] = useState('')
  // webhook — headers never pre-filled (backend only returns has_headers)
  const [webhookUrl, setWebhookUrl] = useState(editing?.config.url ?? '')
  const [webhookMethod, setWebhookMethod] = useState(editing?.config.method ?? 'POST')
  const [webhookHeaders, setWebhookHeaders] = useState('')

  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const emailBlocked = channel === 'email' && smtpEnabled === false

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (emailBlocked) return

    let configData: Record<string, unknown> = {}
    if (channel === 'email') {
      configData = { to_email: toEmail.trim() }
    } else if (channel === 'gotify') {
      // blank token → preserved server-side via fallback to existing
      configData = { server_url: gotifyUrl.trim(), token: gotifyToken }
    } else if (channel === 'webhook') {
      let parsed: Record<string, string> | undefined
      if (webhookHeaders.trim()) {
        try { parsed = JSON.parse(webhookHeaders) }
        catch { setError('Headers must be valid JSON (e.g. {"Key": "Value"}).'); return }
      }
      configData = {
        url: webhookUrl.trim(),
        method: webhookMethod,
        ...(parsed !== undefined ? { headers: parsed } : {}),
      }
    }

    setSaving(true)
    setError(null)
    try {
      const saved = isEdit
        ? await updateNotificationConfig(editing.id, { name, is_enabled: isEnabled, is_default: isDefault, config: configData })
        : await createNotificationConfig({ name, channel, is_enabled: isEnabled, is_default: isDefault, config: configData })
      onSaved(saved)
      onClose()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Save failed.')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/50 p-4 pt-16"
      role="dialog" aria-modal="true"
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}
    >
      <div className="w-full max-w-md rounded-lg border border-border bg-card shadow-lg">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <h2 className="text-sm font-semibold text-foreground">{isEdit ? 'Edit channel' : 'Add channel'}</h2>
          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={onClose} aria-label="Close">
            <X size={14} aria-hidden="true" />
          </Button>
        </div>
        <form onSubmit={handleSubmit} className="flex flex-col gap-4 p-5">
          <div>
            <label htmlFor={`${uid}-name`} className={LABEL}>Name <span className="text-destructive">*</span></label>
            <input id={`${uid}-name`} type="text" className={INPUT} value={name} required
              onChange={e => setName(e.target.value)} disabled={saving} />
          </div>

          {!isEdit && (
            <div>
              <label htmlFor={`${uid}-ch`} className={LABEL}>Channel type</label>
              <select id={`${uid}-ch`} className={INPUT} value={channel}
                onChange={e => setChannel(e.target.value as Channel)} disabled={saving}>
                <option value="email">Email</option>
                <option value="gotify">Gotify</option>
                <option value="webhook">Webhook</option>
              </select>
            </div>
          )}

          {emailBlocked && (
            <div className="flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2.5 text-xs text-amber-700 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-400">
              <AlertTriangle size={13} className="mt-0.5 shrink-0" aria-hidden="true" />
              SMTP is not configured or disabled. Email channels cannot be created or tested.
            </div>
          )}

          {channel === 'email' && (
            <div>
              <label htmlFor={`${uid}-email`} className={LABEL}>Recipient override <span className="text-muted-foreground">(optional)</span></label>
              <input id={`${uid}-email`} type="email" className={INPUT} value={toEmail}
                onChange={e => setToEmail(e.target.value)} disabled={saving}
                placeholder="Leave blank to use your account email" />
            </div>
          )}

          {channel === 'gotify' && (
            <>
              <div>
                <label htmlFor={`${uid}-gurl`} className={LABEL}>Server URL <span className="text-destructive">*</span></label>
                <input id={`${uid}-gurl`} type="url" className={INPUT} value={gotifyUrl}
                  onChange={e => setGotifyUrl(e.target.value)} required disabled={saving}
                  placeholder="http://gotify.example.com" />
              </div>
              <div>
                <label htmlFor={`${uid}-gtok`} className={LABEL}>
                  App token{!isEdit && <span className="text-destructive"> *</span>}
                  {isEdit && editing.config.has_token && (
                    <span className="ml-1 font-normal text-muted-foreground">(blank = keep existing)</span>
                  )}
                </label>
                <input id={`${uid}-gtok`} type="password" className={INPUT} value={gotifyToken}
                  onChange={e => setGotifyToken(e.target.value)} required={!isEdit}
                  disabled={saving} autoComplete="new-password" />
              </div>
            </>
          )}

          {channel === 'webhook' && (
            <>
              <div>
                <label htmlFor={`${uid}-wurl`} className={LABEL}>URL <span className="text-destructive">*</span></label>
                <input id={`${uid}-wurl`} type="url" className={INPUT} value={webhookUrl}
                  onChange={e => setWebhookUrl(e.target.value)} required disabled={saving}
                  placeholder="https://hooks.example.com/notify" />
              </div>
              <div>
                <label htmlFor={`${uid}-wmeth`} className={LABEL}>Method</label>
                <select id={`${uid}-wmeth`} className={INPUT} value={webhookMethod}
                  onChange={e => setWebhookMethod(e.target.value)} disabled={saving}>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                </select>
              </div>
              <div>
                <label htmlFor={`${uid}-whdr`} className={LABEL}>
                  Headers (JSON)
                  {isEdit && editing.config.has_headers && (
                    <span className="ml-1 font-normal text-muted-foreground">(blank = keep existing)</span>
                  )}
                </label>
                <textarea id={`${uid}-whdr`}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50"
                  rows={3} value={webhookHeaders} onChange={e => setWebhookHeaders(e.target.value)}
                  disabled={saving} placeholder='{"Authorization": "Bearer token"}' />
              </div>
            </>
          )}

          <div className="flex gap-4">
            <label className="flex items-center gap-2 text-sm text-foreground">
              <input type="checkbox" checked={isEnabled} onChange={e => setIsEnabled(e.target.checked)}
                disabled={saving} className="h-4 w-4 rounded border-input accent-primary" />
              Enabled
            </label>
            <label className="flex items-center gap-2 text-sm text-foreground">
              <input type="checkbox" checked={isDefault} onChange={e => setIsDefault(e.target.checked)}
                disabled={saving} className="h-4 w-4 rounded border-input accent-primary" />
              Default
            </label>
          </div>

          {error && <p className="text-sm text-destructive">{error}</p>}

          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <Button type="button" variant="outline" size="sm" onClick={onClose} disabled={saving}>Cancel</Button>
            <Button type="submit" size="sm" disabled={saving || emailBlocked}>
              {saving && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
              {isEdit ? 'Save changes' : 'Add channel'}
            </Button>
          </div>
        </form>
      </div>
    </div>
  )
}
