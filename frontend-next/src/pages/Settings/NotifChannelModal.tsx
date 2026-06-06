import { useState, useId } from 'react'
import { X, Loader2, AlertTriangle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { createNotificationConfig, updateNotificationConfig } from '@/api/notifications'
import { ApiError } from '@/api/client'
import type { NotificationConfig } from '@/pages/Notifications/notifications.types'
import { useI18n } from '@/i18n'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'

type Channel = 'email' | 'gotify' | 'webhook'

const ALL_CHANNELS: { value: Channel; label: string }[] = [
  { value: 'email',   label: 'Email'   },
  { value: 'gotify',  label: 'Gotify'  },
  { value: 'webhook', label: 'Webhook' },
]

interface Props {
  editing: NotificationConfig | null
  smtpEnabled: boolean | null
  onClose: () => void
  onSaved: (cfg: NotificationConfig) => void
}

export default function NotifChannelModal({ editing, smtpEnabled, onClose, onSaved }: Props) {
  const { t } = useI18n()
  const isEdit = editing !== null
  const uid = useId()

  const availableChannels = (!isEdit && smtpEnabled === false)
    ? ALL_CHANNELS.filter((ch) => ch.value !== 'email')
    : ALL_CHANNELS

  const [name, setName] = useState(editing?.name ?? '')
  const [channel, setChannel] = useState<Channel>(() => {
    if (editing) return (editing.channel as Channel) ?? 'email'
    return smtpEnabled === false ? 'gotify' : 'email'
  })
  const [isEnabled, setIsEnabled] = useState(editing?.is_enabled ?? true)
  const [toEmail, setToEmail] = useState(editing?.config.to_email ?? '')
  const [gotifyUrl, setGotifyUrl] = useState(editing?.config.server_url ?? '')
  const [gotifyToken, setGotifyToken] = useState('')
  const [webhookUrl, setWebhookUrl] = useState(editing?.config.url ?? '')
  const [webhookMethod, setWebhookMethod] = useState(editing?.config.method ?? 'POST')
  const [webhookHeaders, setWebhookHeaders] = useState('')

  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const emailUnavailable = channel === 'email' && smtpEnabled === false
  const emailBlocked = emailUnavailable && !isEdit

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (emailBlocked) return

    let configData: Record<string, unknown> = {}
    if (channel === 'email') {
      configData = { to_email: toEmail.trim() }
    } else if (channel === 'gotify') {
      configData = { server_url: gotifyUrl.trim(), token: gotifyToken }
    } else if (channel === 'webhook') {
      let parsed: Record<string, string> | undefined
      if (webhookHeaders.trim()) {
        try { parsed = JSON.parse(webhookHeaders) }
        catch { setError(t('invalidHeadersJson')); return }
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
        ? await updateNotificationConfig(editing.id, { name, is_enabled: isEnabled, config: configData })
        : await createNotificationConfig({ name, channel, is_enabled: isEnabled, config: configData })
      onSaved(saved)
      onClose()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('saveFailed'))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/50 p-4 pt-16"
      role="dialog" aria-modal="true"
      aria-label={isEdit ? t('editChannel') : t('addChannel')}
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose() }}
    >
      <div className="w-full max-w-md rounded-lg border border-border bg-card shadow-lg">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <h2 className="text-sm font-semibold text-foreground">{isEdit ? t('editChannel') : t('addChannel')}</h2>
          <Button variant="ghost" size="icon" className="h-7 w-7" onClick={onClose} aria-label={t('close')}>
            <X size={14} aria-hidden="true" />
          </Button>
        </div>
        <form onSubmit={handleSubmit} className="flex flex-col gap-4 p-5">
          <div>
            <label htmlFor={`${uid}-name`} className={LABEL}>{t('colName')} <span className="text-destructive">*</span></label>
            <input id={`${uid}-name`} type="text" className={INPUT} value={name} required
              onChange={e => setName(e.target.value)} disabled={saving} />
          </div>

          {!isEdit && (
            <div>
              <label htmlFor={`${uid}-ch`} className={LABEL}>{t('labelChannelType')}</label>
              <select id={`${uid}-ch`} className={INPUT} value={channel}
                onChange={e => setChannel(e.target.value as Channel)} disabled={saving}>
                {availableChannels.map(ch => (
                  <option key={ch.value} value={ch.value}>{ch.label}</option>
                ))}
              </select>
            </div>
          )}

          {emailUnavailable && (
            <div className="flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2.5 text-xs text-amber-700 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-400">
              <AlertTriangle size={13} className="mt-0.5 shrink-0" aria-hidden="true" />
              {isEdit ? t('smtpEditWarning') : t('smtpCreateWarning')}
            </div>
          )}

          {channel === 'email' && (
            <div>
              <label htmlFor={`${uid}-email`} className={LABEL}>
                {t('labelRecipientOverride')} <span className="text-muted-foreground">(optional)</span>
              </label>
              <input id={`${uid}-email`} type="email" className={INPUT} value={toEmail}
                onChange={e => setToEmail(e.target.value)} disabled={saving}
                placeholder={t('recipientPlaceholder')} />
            </div>
          )}

          {channel === 'gotify' && (
            <>
              <div>
                <label htmlFor={`${uid}-gurl`} className={LABEL}>{t('labelServerUrl')} <span className="text-destructive">*</span></label>
                <input id={`${uid}-gurl`} type="url" className={INPUT} value={gotifyUrl}
                  onChange={e => setGotifyUrl(e.target.value)} required disabled={saving}
                  placeholder="http://gotify.example.com" />
              </div>
              <div>
                <label htmlFor={`${uid}-gtok`} className={LABEL}>
                  {t('labelAppToken')}{!isEdit && <span className="text-destructive"> *</span>}
                  {isEdit && editing.config.has_token && (
                    <span className="ml-1 font-normal text-muted-foreground">{t('labelKeepExisting')}</span>
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
                <label htmlFor={`${uid}-wmeth`} className={LABEL}>{t('labelMethod')}</label>
                <select id={`${uid}-wmeth`} className={INPUT} value={webhookMethod}
                  onChange={e => setWebhookMethod(e.target.value)} disabled={saving}>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                </select>
              </div>
              <div>
                <label htmlFor={`${uid}-whdr`} className={LABEL}>
                  {t('labelHeaders')}
                  {isEdit && editing.config.has_headers && (
                    <span className="ml-1 font-normal text-muted-foreground">{t('labelKeepExisting')}</span>
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
              {t('labelEnabled')}
            </label>
          </div>

          {error && (
            <p className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
              {error}
            </p>
          )}

          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <Button type="button" variant="outline" size="sm" onClick={onClose} disabled={saving}>{t('cancel')}</Button>
            <Button type="submit" size="sm" disabled={saving || emailBlocked}>
              {saving && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
              {isEdit ? t('saveChanges') : t('addChannel')}
            </Button>
          </div>
        </form>
      </div>
    </div>
  )
}
