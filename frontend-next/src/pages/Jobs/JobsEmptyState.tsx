import { Settings2, Inbox, SearchX, PlusCircle } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { useI18n } from '@/i18n'

function EmptyIcon({ icon: Icon }: { icon: typeof Inbox }) {
  return (
    <div className="flex h-12 w-12 items-center justify-center rounded-full bg-muted">
      <Icon size={20} className="text-muted-foreground" aria-hidden="true" />
    </div>
  )
}

export function EmptyNoProvider() {
  const { t } = useI18n()
  return (
    <div className="flex flex-col items-center justify-center gap-4 px-4 py-16 text-center">
      <EmptyIcon icon={Settings2} />
      <div className="space-y-1">
        <p className="text-sm font-medium text-foreground">{t('emptyNoProvider')}</p>
        <p className="text-sm text-muted-foreground">{t('emptyNoProviderDesc')}</p>
      </div>
      <Button asChild size="sm" variant="outline">
        <Link to="/settings?section=providers">{t('configureProviders')}</Link>
      </Button>
    </div>
  )
}

export function EmptyNoJobs() {
  const { t } = useI18n()
  return (
    <div className="flex flex-col items-center justify-center gap-4 px-4 py-16 text-center">
      <EmptyIcon icon={Inbox} />
      <div className="space-y-1">
        <p className="text-sm font-medium text-foreground">{t('emptyNoJobs')}</p>
        <p className="text-sm text-muted-foreground">{t('emptyNoJobsDesc')}</p>
      </div>
      <Button asChild size="sm">
        <Link to="/jobs/new">
          <PlusCircle size={14} aria-hidden="true" />
          {t('navNewJob')}
        </Link>
      </Button>
    </div>
  )
}

export function EmptyFiltered({ onClearFilters }: { onClearFilters: () => void }) {
  const { t } = useI18n()
  return (
    <div className="flex flex-col items-center justify-center gap-4 px-4 py-16 text-center">
      <EmptyIcon icon={SearchX} />
      <div className="space-y-1">
        <p className="text-sm font-medium text-foreground">{t('emptyFiltered')}</p>
        <p className="text-sm text-muted-foreground">{t('emptyFilteredDesc')}</p>
      </div>
      <Button size="sm" variant="outline" onClick={onClearFilters}>
        {t('clearFilters')}
      </Button>
    </div>
  )
}
