import { Bell, CalendarDays, AlertCircle, Clock } from 'lucide-react'
import MetricCard from '@/components/common/MetricCard'
import { useI18n } from '@/i18n'

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
  const { t } = useI18n()
  const v = (n: number): string | number => (loading ? '…' : n)

  return (
    <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
      <MetricCard
        label={t('notifEnabledRules')}
        value={v(enabledRules)}
        icon={Bell}
        description={t('notifActiveRulesDesc')}
      />
      <MetricCard
        label={t('notifEventsToday')}
        value={v(eventsToday)}
        icon={CalendarDays}
        description={t('notifSinceMidnight')}
        iconClassName="bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400"
      />
      <MetricCard
        label={t('notifFailedDlv')}
        value={v(failedDeliveries)}
        icon={AlertCircle}
        description={t('notifUndelivered')}
        iconClassName="bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400"
      />
      <MetricCard
        label={t('notifPending')}
        value={v(pending)}
        icon={Clock}
        description={t('notifQueuedDlv')}
        iconClassName="bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400"
      />
    </div>
  )
}
