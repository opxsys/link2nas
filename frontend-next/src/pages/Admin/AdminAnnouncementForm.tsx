import { useState, useEffect } from 'react'
import { Loader2, XCircle } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { createAnnouncement, updateAnnouncement } from '@/api/admin-announcements'
import { useSmtpStatus } from '@/lib/useSmtpStatus'
import type { RealAnnouncement, AnnouncementPayload, AnnouncementType, AnnouncementSeverityLevel } from './admin.types'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const SELECT = INPUT
const TEXTAREA = 'w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'
const CHECK = 'h-4 w-4 rounded border-input accent-primary disabled:opacity-50'
const CHECK_ROW = 'flex items-center gap-2.5'
const CHECK_LABEL = 'text-sm text-foreground'

function toDatetimeLocal(iso: string | null): string {
  return iso ? iso.slice(0, 16) : ''
}

const EMPTY: AnnouncementPayload = {
  title: '', body: '', type: 'news', severity: 'info',
  is_active: true, show_as_banner: false, require_acknowledgement: false,
  track_open: false, send_email: false, starts_at: null, ends_at: null,
}

interface Props {
  ann: RealAnnouncement | null
  onSave: (ann: RealAnnouncement) => void
  onCancel: () => void
}

export default function AdminAnnouncementForm({ ann, onSave, onCancel }: Props) {
  const { smtpAvailable, smtpLoading } = useSmtpStatus()
  const [fields, setFields] = useState<AnnouncementPayload>(EMPTY)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  // Force send_email off when SMTP is confirmed unavailable.
  useEffect(() => {
    if (!smtpLoading && !smtpAvailable) {
      setFields((p) => ({ ...p, send_email: false }))
    }
  }, [smtpAvailable, smtpLoading])

  useEffect(() => {
    if (ann) {
      setFields({
        title: ann.title, body: ann.body, type: ann.type, severity: ann.severity,
        is_active: ann.is_active, show_as_banner: ann.show_as_banner,
        require_acknowledgement: ann.require_acknowledgement, track_open: ann.track_open,
        send_email: ann.send_email, starts_at: ann.starts_at, ends_at: ann.ends_at,
      })
    } else {
      setFields(EMPTY)
    }
    setError('')
  }, [ann])

  function set<K extends keyof AnnouncementPayload>(key: K, value: AnnouncementPayload[K]) {
    setFields((p) => ({ ...p, [key]: value }))
    if (error) setError('')
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setSaving(true)
    setError('')
    try {
      const payload: AnnouncementPayload = {
        ...fields,
        title: fields.title.trim(),
        body: fields.body.trim(),
        starts_at: fields.starts_at || null,
        ends_at: fields.ends_at || null,
      }
      const saved = ann
        ? await updateAnnouncement(ann.id, payload)
        : await createAnnouncement(payload)
      onSave(saved)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Save failed.')
      setSaving(false)
    }
  }

  const title = ann ? 'Edit Announcement' : 'New Announcement'

  return (
    <SectionCard title={title}>
      <form onSubmit={handleSubmit} className="flex flex-col gap-5">
        <div>
          <label htmlFor="ann-title" className={LABEL}>Title <span className="text-destructive">*</span></label>
          <input id="ann-title" type="text" className={INPUT} value={fields.title} disabled={saving}
            required onChange={(e) => set('title', e.target.value)} />
        </div>

        <div>
          <label htmlFor="ann-body" className={LABEL}>Body <span className="text-destructive">*</span></label>
          <textarea id="ann-body" className={TEXTAREA} rows={5} value={fields.body} disabled={saving}
            required onChange={(e) => set('body', e.target.value)} />
        </div>

        <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
          <div>
            <label htmlFor="ann-type" className={LABEL}>Type</label>
            <select id="ann-type" className={SELECT} value={fields.type} disabled={saving}
              onChange={(e) => set('type', e.target.value as AnnouncementType)}>
              <option value="news">News</option>
              <option value="maintenance">Maintenance</option>
              <option value="incident">Incident</option>
              <option value="security">Security</option>
            </select>
          </div>
          <div>
            <label htmlFor="ann-severity" className={LABEL}>Severity</label>
            <select id="ann-severity" className={SELECT} value={fields.severity} disabled={saving}
              onChange={(e) => set('severity', e.target.value as AnnouncementSeverityLevel)}>
              <option value="info">Info</option>
              <option value="warning">Warning</option>
              <option value="critical">Critical</option>
            </select>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
          <div>
            <label htmlFor="ann-starts" className={LABEL}>Starts at <span className="text-muted-foreground">(optional)</span></label>
            <input id="ann-starts" type="datetime-local" className={INPUT}
              value={toDatetimeLocal(fields.starts_at)} disabled={saving}
              onChange={(e) => set('starts_at', e.target.value || null)} />
          </div>
          <div>
            <label htmlFor="ann-ends" className={LABEL}>Ends at <span className="text-muted-foreground">(optional)</span></label>
            <input id="ann-ends" type="datetime-local" className={INPUT}
              value={toDatetimeLocal(fields.ends_at)} disabled={saving}
              onChange={(e) => set('ends_at', e.target.value || null)} />
          </div>
        </div>

        <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
          {([
            ['is_active',              'Active (visible to users)'],
            ['show_as_banner',         'Show as banner'],
            ['require_acknowledgement','Require acknowledgement'],
            ['track_open',             'Track opens'],
          ] as [keyof AnnouncementPayload, string][]).map(([key, label]) => (
            <div key={key} className={CHECK_ROW}>
              <input id={`ann-${key}`} type="checkbox" className={CHECK}
                checked={fields[key] as boolean} disabled={saving}
                onChange={(e) => set(key, e.target.checked)} />
              <label htmlFor={`ann-${key}`} className={CHECK_LABEL}>{label}</label>
            </div>
          ))}
        </div>

        <div className="flex flex-col gap-1.5">
          <div className={CHECK_ROW}>
            <input
              id="ann-send_email"
              type="checkbox"
              className={CHECK}
              checked={fields.send_email}
              disabled={saving || (!smtpLoading && !smtpAvailable)}
              onChange={(e) => set('send_email', e.target.checked)}
            />
            <label htmlFor="ann-send_email" className={!smtpLoading && !smtpAvailable ? 'text-sm text-muted-foreground' : CHECK_LABEL}>
              Send email notification
            </label>
          </div>
          {!smtpLoading && !smtpAvailable && (
            <p className="ml-6 text-xs text-amber-700 dark:text-amber-400">
              SMTP is not configured or disabled. Email sending is unavailable.
            </p>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" size="sm" disabled={saving}>
            {saving && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
            {ann ? 'Save changes' : 'Create'}
          </Button>
          <Button type="button" size="sm" variant="outline" disabled={saving} onClick={onCancel}>
            Cancel
          </Button>
          {error && (
            <span className="flex items-center gap-1.5 text-sm text-red-700 dark:text-red-400">
              <XCircle size={14} aria-hidden="true" /> {error}
            </span>
          )}
        </div>

      </form>
    </SectionCard>
  )
}
