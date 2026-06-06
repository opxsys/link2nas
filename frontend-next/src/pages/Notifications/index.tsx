import { useMemo } from 'react'
import PageHeader from '@/components/layout/PageHeader'
import { useNotificationsState } from './useNotificationsState'
import NotificationSummaryCards from './NotificationSummaryCards'
import NotificationRulesTable from './NotificationRulesTable'
import NotificationEventsTimeline from './NotificationEventsTimeline'
import NotificationChannelsPanel from './NotificationChannelsPanel'
import NotificationTestPanel from './NotificationTestPanel'
import { useI18n } from '@/i18n'

function isToday(isoStr: string): boolean {
  const d = new Date(isoStr)
  const now = new Date()
  return (
    d.getFullYear() === now.getFullYear() &&
    d.getMonth() === now.getMonth() &&
    d.getDate() === now.getDate()
  )
}

export default function Notifications() {
  const { t } = useI18n()
  const state = useNotificationsState()

  const summary = useMemo(
    () => ({
      enabledRules: state.rules.filter((r) => r.is_enabled).length,
      eventsToday: state.events.filter((e) => isToday(e.created_at)).length,
      failedDeliveries: state.events.filter((e) => e.status === 'failed').length,
      pending: state.events.filter((e) => e.status === 'pending').length,
    }),
    [state.rules, state.events],
  )

  return (
    <>
      <PageHeader
        title={t('notifPageTitle')}
        description={t('notifPageDesc')}
      />
      <div className="flex flex-col gap-6">
        <NotificationSummaryCards {...summary} loading={state.loading} />
        <NotificationRulesTable
          rules={state.rules}
          configs={state.configs}
          loading={state.loading}
          error={state.error}
          onToggle={state.toggleRule}
        />
        <div className="grid gap-6 lg:grid-cols-2">
          <NotificationEventsTimeline
            events={state.events}
            configs={state.configs}
            loading={state.loading}
            error={state.error}
          />
          <NotificationChannelsPanel
            configs={state.configs}
            smtpEnabled={state.smtpEnabled}
            loading={state.loading}
            error={state.error}
          />
        </div>
        <NotificationTestPanel
          configs={state.configs}
          smtpEnabled={state.smtpEnabled}
          testConfigId={state.testConfigId}
          testStatus={state.testStatus}
          onConfigChange={state.setTestConfigId}
          onSend={state.runTest}
        />
      </div>
    </>
  )
}
