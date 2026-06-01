import { useState, useEffect, useCallback } from 'react'
import { Loader2, AlertCircle, ArrowLeft } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { getAnnouncementTracking } from '@/api/admin-announcements'
import type { AnnouncementTracking, AnnouncementTrackingRead } from './admin.types'

function fmt(iso: string | null | undefined): string {
  return iso ? new Date(iso).toLocaleString() : '—'
}

function StatBox({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border border-border bg-muted/20 p-3 text-center">
      <p className="text-xl font-semibold text-foreground">{value}</p>
      <p className="mt-0.5 text-xs text-muted-foreground">{label}</p>
    </div>
  )
}

function ReadRow({ r }: { r: AnnouncementTrackingRead }) {
  return (
    <tr className="hover:bg-muted/30">
      <td className="px-3 py-2 text-sm text-foreground">{r.display_name || r.email || r.user_id}</td>
      <td className="px-3 py-2 text-xs text-muted-foreground">{fmt(r.opened_at)}</td>
      <td className="px-3 py-2 text-xs text-muted-foreground">{fmt(r.read_at)}</td>
      <td className="px-3 py-2 text-xs text-muted-foreground">{fmt(r.acknowledged_at)}</td>
      <td className="px-3 py-2 text-xs text-muted-foreground">
        {r.email_status
          ? <span className={r.email_status === 'sent' ? 'text-emerald-700 dark:text-emerald-400' : 'text-amber-700 dark:text-amber-400'}>{r.email_status}</span>
          : '—'}
        {r.email_error && <span className="ml-1 text-red-600 dark:text-red-400" title={r.email_error}>(!)</span>}
      </td>
    </tr>
  )
}

interface Props {
  id: string
  onBack: () => void
}

export default function AdminAnnouncementTracking({ id, onBack }: Props) {
  const [data, setData] = useState<AnnouncementTracking | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      setData(await getAnnouncementTracking(id))
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load tracking data.')
    } finally {
      setLoading(false)
    }
  }, [id])

  useEffect(() => { load() }, [load])

  return (
    <div className="flex flex-col gap-4">
      <Button size="sm" variant="outline" className="w-fit" onClick={onBack}>
        <ArrowLeft size={13} className="mr-1.5" aria-hidden="true" /> Back to list
      </Button>

      {loading && (
        <div className="flex items-center gap-2 py-8 text-muted-foreground">
          <Loader2 size={18} className="animate-spin" aria-hidden="true" />
          <span className="text-sm">Loading tracking data…</span>
        </div>
      )}

      {error && (
        <div className="flex items-start gap-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
          <AlertCircle size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
          <div>
            <p className="font-medium">Failed to load tracking data</p>
            <p className="mt-0.5 text-xs">{error}</p>
            <Button size="sm" variant="outline" className="mt-3" onClick={load}>Retry</Button>
          </div>
        </div>
      )}

      {data && (
        <>
          <SectionCard title={data.announcement.title} description="Delivery and engagement statistics.">
            <div className="grid grid-cols-3 gap-3 sm:grid-cols-6">
              <StatBox label="Sent"           value={data.stats.sent_count} />
              <StatBox label="Opened"         value={data.stats.opened_count} />
              <StatBox label="Read"           value={data.stats.read_count} />
              <StatBox label="Acknowledged"   value={data.stats.acknowledged_count} />
              <StatBox label="Failed"         value={data.stats.failed_count} />
              <StatBox label="Email targets"  value={data.stats.targeted_email_recipients} />
            </div>
          </SectionCard>

          <SectionCard title="Per-User Activity" bodyClassName="p-0">
            {data.reads.length === 0 ? (
              <p className="px-4 py-4 text-sm text-muted-foreground">No activity recorded yet.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border">
                      {['User', 'Opened', 'Read', 'Acknowledged', 'Email'].map((h) => (
                        <th key={h} className="px-3 pb-2.5 pt-3 text-left text-xs font-medium text-muted-foreground">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {data.reads.map((r) => <ReadRow key={r.user_id} r={r} />)}
                  </tbody>
                </table>
              </div>
            )}
          </SectionCard>
        </>
      )}
    </div>
  )
}
