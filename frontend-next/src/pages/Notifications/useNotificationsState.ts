import { useState, useEffect, useCallback } from 'react'
import { useI18n } from '@/i18n'
import type {
  NotificationConfig,
  NotificationRule,
  NotificationEvent,
  TestStatus,
} from './notifications.types'
import {
  listNotificationConfigs,
  listNotificationRules,
  listUserNotificationEvents,
  updateNotificationRule,
  testNotificationConfig,
} from '@/api/notifications'
import { getSmtpSettings } from '@/api/admin-smtp'
import { ApiError } from '@/api/client'
import { isUserNotificationEvent } from '@/lib/notification-filters'

export interface NotificationsState {
  configs: NotificationConfig[]
  rules: NotificationRule[]
  events: NotificationEvent[]
  smtpEnabled: boolean | null  // null = unknown (non-admin or fetch failed)
  loading: boolean
  error: string | null
  testStatus: TestStatus
  testConfigId: string
  setTestConfigId: (id: string) => void
  toggleRule: (id: string, enabled: boolean) => Promise<void>
  runTest: () => Promise<void>
}

export function useNotificationsState(): NotificationsState {
  const { t } = useI18n()
  const [configs, setConfigs] = useState<NotificationConfig[]>([])
  const [rules, setRules] = useState<NotificationRule[]>([])
  const [events, setEvents] = useState<NotificationEvent[]>([])
  const [smtpEnabled, setSmtpEnabled] = useState<boolean | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [testStatus, setTestStatus] = useState<TestStatus>('idle')
  const [testConfigId, setTestConfigId] = useState<string>('')

  useEffect(() => {
    let cancelled = false

    async function load() {
      setLoading(true)
      setError(null)
      try {
        const [cfgs, rlz, evts] = await Promise.all([
          listNotificationConfigs(),
          listNotificationRules(),
          listUserNotificationEvents(50),
        ])
        if (cancelled) return
        setConfigs(cfgs)
        setRules(rlz)
        setEvents(evts.filter(isUserNotificationEvent))
        if (cfgs.length > 0 && !testConfigId) {
          setTestConfigId(cfgs[0].id)
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof ApiError ? err.message : t('notificationsLoadFailed'))
        }
      } finally {
        if (!cancelled) setLoading(false)
      }

      // SMTP check is best-effort — 403 from non-admins leaves smtpEnabled as null
      try {
        const smtp = await getSmtpSettings()
        if (!cancelled) setSmtpEnabled(smtp.enabled && !!smtp.host)
      } catch {
        // leave as null (unknown)
      }
    }

    load()
    return () => { cancelled = true }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const toggleRule = useCallback(async (id: string, enabled: boolean) => {
    setRules(prev => prev.map(r => r.id === id ? { ...r, is_enabled: enabled } : r))
    try {
      const updated = await updateNotificationRule(id, { is_enabled: enabled })
      setRules(prev => prev.map(r => r.id === id ? updated : r))
    } catch {
      setRules(prev => prev.map(r => r.id === id ? { ...r, is_enabled: !enabled } : r))
    }
  }, [])

  const runTest = useCallback(async () => {
    if (!testConfigId) return
    setTestStatus('sending')
    try {
      await testNotificationConfig(testConfigId)
      setTestStatus('sent')
    } catch {
      setTestStatus('failed')
    }
  }, [testConfigId])

  return {
    configs,
    rules,
    events,
    smtpEnabled,
    loading,
    error,
    testStatus,
    testConfigId,
    setTestConfigId,
    toggleRule,
    runTest,
  }
}
