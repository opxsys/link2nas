import { useState, useEffect } from 'react'
import { Bell, Loader2, AlertTriangle } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { listNotificationRules, updateNotificationRule } from '@/api/notifications'
import { getSmtpSettings } from '@/api/admin-smtp'
import { listNotificationConfigs } from '@/api/notifications'
import { ApiError } from '@/api/client'
import type { NotificationRule, NotificationConfig } from '@/pages/Notifications/notifications.types'

const CHANNEL_LABEL: Record<string, string> = {
  email: 'Email',
  gotify: 'Gotify',
  webhook: 'Webhook',
}

export default function NotificationSettings() {
  const [rules, setRules] = useState<NotificationRule[]>([])
  const [configs, setConfigs] = useState<NotificationConfig[]>([])
  const [smtpEnabled, setSmtpEnabled] = useState<boolean | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    async function load() {
      setLoading(true)
      setError(null)
      try {
        const [rlz, cfgs] = await Promise.all([
          listNotificationRules(),
          listNotificationConfigs(),
        ])
        if (!cancelled) {
          setRules(rlz)
          setConfigs(cfgs)
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof ApiError ? err.message : 'Failed to load notification settings')
        }
      } finally {
        if (!cancelled) setLoading(false)
      }
      try {
        const smtp = await getSmtpSettings()
        if (!cancelled) setSmtpEnabled(smtp.enabled && !!smtp.host)
      } catch {
        // non-admin: leave as null
      }
    }
    load()
    return () => { cancelled = true }
  }, [])

  function channelForRule(rule: NotificationRule): string {
    const cfg = configs.find(c => c.id === rule.config_id)
    if (!cfg) return '—'
    return CHANNEL_LABEL[cfg.channel] ?? cfg.channel
  }

  function isEmailRule(rule: NotificationRule): boolean {
    return configs.find(c => c.id === rule.config_id)?.channel === 'email'
  }

  async function toggleRule(id: string) {
    const rule = rules.find(r => r.id === id)
    if (!rule) return
    const next = !rule.is_enabled
    setRules(prev => prev.map(r => r.id === id ? { ...r, is_enabled: next } : r))
    try {
      const updated = await updateNotificationRule(id, { is_enabled: next })
      setRules(prev => prev.map(r => r.id === id ? updated : r))
    } catch {
      setRules(prev => prev.map(r => r.id === id ? { ...r, is_enabled: !next } : r))
    }
  }

  const smtpDisabled = smtpEnabled === false

  return (
    <SectionCard
      title="Notification Rules"
      description="Configure when and how you receive notifications."
      actions={
        <Button variant="outline" size="sm" disabled>
          Add rule
        </Button>
      }
    >
      {loading && (
        <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
          <Loader2 size={14} className="animate-spin" aria-hidden="true" />
          Loading…
        </div>
      )}
      {!loading && error && (
        <p className="py-4 text-sm text-destructive">{error}</p>
      )}
      {!loading && !error && rules.length === 0 && (
        <p className="py-4 text-sm text-muted-foreground italic">No notification rules configured.</p>
      )}
      {!loading && !error && rules.length > 0 && (
        <div className="flex flex-col gap-3">
          {smtpDisabled && rules.some(r => isEmailRule(r)) && (
            <div className="flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2.5 text-sm text-amber-700 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-400">
              <AlertTriangle size={14} className="mt-0.5 shrink-0" aria-hidden="true" />
              SMTP is not configured or disabled. Email sending is unavailable.
            </div>
          )}
          {rules.map((rule) => {
            const emailBlocked = isEmailRule(rule) && smtpDisabled
            return (
              <div
                key={rule.id}
                className={`flex items-center gap-4 rounded-lg border border-border p-4 ${emailBlocked ? 'opacity-60' : ''}`}
              >
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-muted text-foreground">
                  <Bell size={16} aria-hidden="true" />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-foreground">{rule.name}</p>
                  <p className="text-xs text-muted-foreground">Channel: {channelForRule(rule)}</p>
                </div>
                <label className={`flex items-center gap-2 ${emailBlocked ? 'cursor-not-allowed' : 'cursor-pointer'}`}>
                  <span className="text-xs text-muted-foreground">
                    {rule.is_enabled ? 'Enabled' : 'Disabled'}
                  </span>
                  <input
                    type="checkbox"
                    checked={rule.is_enabled}
                    onChange={() => !emailBlocked && toggleRule(rule.id)}
                    disabled={emailBlocked}
                    className="h-4 w-4 rounded border-input accent-primary disabled:opacity-50"
                    aria-label={`${rule.name} notification`}
                  />
                </label>
              </div>
            )
          })}
        </div>
      )}
    </SectionCard>
  )
}
