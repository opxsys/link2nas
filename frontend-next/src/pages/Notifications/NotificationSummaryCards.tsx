import { Bell, CalendarDays, AlertCircle, Clock } from 'lucide-react'
import MetricCard from '@/components/common/MetricCard'

interface Props {
  enabledRules: number
  eventsToday: number
  failedDeliveries: number
  pending: number
  loading?: boolean
}

export default function NotificationSummaryCards({
  enabledRules,
  eventsToday,
  failedDeliveries,
  pending,
  loading,
}: Props) {
  const v = (n: number): string | number => (loading ? '…' : n)

  return (
    <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
      <MetricCard
        label="Enabled Rules"
        value={v(enabledRules)}
        icon={Bell}
        description="Active notification rules"
      />
      <MetricCard
        label="Events Today"
        value={v(eventsToday)}
        icon={CalendarDays}
        description="Since midnight"
        iconClassName="bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400"
      />
      <MetricCard
        label="Failed Deliveries"
        value={v(failedDeliveries)}
        icon={AlertCircle}
        description="Undelivered notifications"
        iconClassName="bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400"
      />
      <MetricCard
        label="Pending"
        value={v(pending)}
        icon={Clock}
        description="Queued for delivery"
        iconClassName="bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400"
      />
    </div>
  )
}
