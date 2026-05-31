import { CheckSquare, Mail, Pencil, Trash2 } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import type { Announcement, AnnouncementStatus } from './admin.types'
import { MOCK_ANNOUNCEMENTS } from './admin-users.mock'

const STATUS_STYLE: Record<AnnouncementStatus, string> = {
  published: 'border-green-200 bg-green-50 text-green-700 dark:border-green-800 dark:bg-green-950 dark:text-green-400',
  draft:     'border-yellow-200 bg-yellow-50 text-yellow-700 dark:border-yellow-800 dark:bg-yellow-950 dark:text-yellow-400',
}

const BADGE = 'inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium capitalize'

function AnnouncementRow({ ann }: { ann: Announcement }) {
  return (
    <li className="flex items-start justify-between gap-4 border-b border-border py-3 last:border-0">
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium text-foreground">{ann.title}</span>
          <span className={`${BADGE} ${STATUS_STYLE[ann.status]}`}>{ann.status}</span>
          {ann.requiresAck && (
            <span className="inline-flex items-center gap-1 rounded-full border border-blue-200 bg-blue-50 px-2 py-0.5 text-xs text-blue-700 dark:border-blue-800 dark:bg-blue-950 dark:text-blue-400">
              <CheckSquare size={10} aria-hidden="true" />
              Requires ack
            </span>
          )}
          {ann.sendEmail && (
            <span className="inline-flex items-center gap-1 rounded-full border border-border bg-muted px-2 py-0.5 text-xs text-muted-foreground">
              <Mail size={10} aria-hidden="true" />
              Email
            </span>
          )}
        </div>
        <p className="mt-1 text-xs text-muted-foreground">
          Created {ann.createdAt}
          {ann.publishedAt ? ` · Published ${ann.publishedAt}` : ' · Not yet published'}
        </p>
      </div>
      <div className="flex shrink-0 items-center gap-1">
        <Button variant="ghost" size="icon" aria-label={`Edit announcement: ${ann.title}`} className="h-7 w-7"><Pencil size={13} /></Button>
        <Button variant="ghost" size="icon" aria-label={`Delete announcement: ${ann.title}`} className="h-7 w-7 text-destructive hover:text-destructive"><Trash2 size={13} /></Button>
      </div>
    </li>
  )
}

export default function AdminAnnouncements() {
  return (
    <SectionCard
      title="Announcements"
      description="Broadcast messages to all users."
      actions={<Button size="sm" variant="outline" disabled>New announcement</Button>}
    >
      <ul>
        {MOCK_ANNOUNCEMENTS.map((ann) => (
          <AnnouncementRow key={ann.id} ann={ann} />
        ))}
      </ul>
    </SectionCard>
  )
}
