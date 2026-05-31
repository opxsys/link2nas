import { Bell, CalendarDays, AlertCircle, Clock } from 'lucide-react'
import MetricCard from '@/components/common/MetricCard'
import { MOCK_SUMMARY } from './notifications.mock'

export default function NotificationSummaryCards() {
  return (
    <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
      <MetricCard
        label="Enabled Rules"
        value={MOCK_SUMMARY.enabledRules}
        icon={Bell}
        description="Active notification rules"
      />
      <MetricCard
        label="Events Today"
        value={MOCK_SUMMARY.eventsToday}
        icon={CalendarDays}
        description="Since midnight"
        iconClassName="bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400"
      />
      <MetricCard
        label="Failed Deliveries"
        value={MOCK_SUMMARY.failedDeliveries}
        icon={AlertCircle}
        description="Undelivered notifications"
        iconClassName="bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400"
      />
      <MetricCard
        label="Pending"
        value={MOCK_SUMMARY.pending}
        icon={Clock}
        description="Queued for delivery"
        iconClassName="bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400"
      />
    </div>
  )
}
