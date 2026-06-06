import { useState } from 'react'
import { cn } from '@/lib/utils'
import AdminSmtp from './AdminSmtp'
import AdminEmailTemplates from './AdminEmailTemplates'
import { useI18n } from '@/i18n'
import type { TranslationKey } from '@/i18n'

type EmailTab = 'smtp' | 'templates'

interface TabDef { id: EmailTab; labelKey: TranslationKey }

const TABS: TabDef[] = [
  { id: 'smtp',      labelKey: 'adminEmailTabSmtp'      },
  { id: 'templates', labelKey: 'adminEmailTabTemplates' },
]

export default function AdminEmails() {
  const { t } = useI18n()
  const [tab, setTab] = useState<EmailTab>('smtp')

  return (
    <div className="flex flex-col gap-4">
      <div className="flex gap-1 rounded-md border border-border bg-muted/40 p-1 w-fit">
        {TABS.map(({ id, labelKey }) => (
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
            {t(labelKey)}
          </button>
        ))}
      </div>

      {tab === 'smtp'      && <AdminSmtp />}
      {tab === 'templates' && <AdminEmailTemplates />}
    </div>
  )
}
