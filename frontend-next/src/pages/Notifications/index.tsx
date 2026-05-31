import PageHeader from '@/components/layout/PageHeader'
import { useNotificationsMockState } from './useNotificationsMockState'
import NotificationSummaryCards from './NotificationSummaryCards'
import NotificationRulesTable from './NotificationRulesTable'
import NotificationEventsTimeline from './NotificationEventsTimeline'
import NotificationChannelsPanel from './NotificationChannelsPanel'
import NotificationTestPanel from './NotificationTestPanel'

export default function Notifications() {
  const { enabledRules, toggleRule, testChannel, setTestChannel, testStatus, runMockTest } =
    useNotificationsMockState()

  return (
    <>
      <PageHeader
        title="Notifications"
        description="Manage your notification rules, channels, and recent events."
      />
      <div className="flex flex-col gap-6">
        <NotificationSummaryCards />
        <NotificationRulesTable enabledRules={enabledRules} onToggle={toggleRule} />
        <div className="grid gap-6 lg:grid-cols-2">
          <NotificationEventsTimeline />
          <NotificationChannelsPanel />
        </div>
        <NotificationTestPanel
          testChannel={testChannel}
          testStatus={testStatus}
          onChannelChange={setTestChannel}
          onSend={runMockTest}
        />
      </div>
    </>
  )
}
