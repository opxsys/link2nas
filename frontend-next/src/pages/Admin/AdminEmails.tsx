import { useState } from 'react'
import { cn } from '@/lib/utils'
import AdminSmtp from './AdminSmtp'
import AdminEmailTemplates from './AdminEmailTemplates'

type EmailTab = 'smtp' | 'templates'

const TABS: { id: EmailTab; label: string }[] = [
  { id: 'smtp',      label: 'SMTP'            },
  { id: 'templates', label: 'Email Templates' },
]

export default function AdminEmails() {
  const [tab, setTab] = useState<EmailTab>('smtp')

  return (
    <div className="flex flex-col gap-4">
      <div className="flex gap-1 rounded-md border border-border bg-muted/40 p-1 w-fit">
        {TABS.map(({ id, label }) => (
          <button
            key={id}
            type="button"
            onClick={() => setTab(id)}
            aria-pressed={tab === id}
            className={cn(
              'rounded px-4 py-1.5 text-sm transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
              tab === id
                ? 'bg-background text-foreground font-medium shadow-sm'
                : 'text-muted-foreground hover:text-foreground',
            )}
          >
            {label}
          </button>
        ))}
      </div>

      {tab === 'smtp'      && <AdminSmtp />}
      {tab === 'templates' && <AdminEmailTemplates />}
    </div>
  )
}
