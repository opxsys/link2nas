import { Settings2, Inbox, SearchX, PlusCircle } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Button } from '@/components/ui/button'

function EmptyIcon({ icon: Icon }: { icon: typeof Inbox }) {
  return (
    <div className="flex h-12 w-12 items-center justify-center rounded-full bg-muted">
      <Icon size={20} className="text-muted-foreground" aria-hidden="true" />
    </div>
  )
}

export function EmptyNoProvider() {
  return (
    <div className="flex flex-col items-center justify-center gap-4 px-4 py-16 text-center">
      <EmptyIcon icon={Settings2} />
      <div className="space-y-1">
        <p className="text-sm font-medium text-foreground">No provider configured</p>
        <p className="text-sm text-muted-foreground">
          Add a download provider before creating jobs.
        </p>
      </div>
      <Button asChild size="sm" variant="outline">
        <Link to="/settings">Configure providers</Link>
      </Button>
    </div>
  )
}

export function EmptyNoJobs() {
  return (
    <div className="flex flex-col items-center justify-center gap-4 px-4 py-16 text-center">
      <EmptyIcon icon={Inbox} />
      <div className="space-y-1">
        <p className="text-sm font-medium text-foreground">No jobs yet</p>
        <p className="text-sm text-muted-foreground">
          Create your first job to start downloading.
        </p>
      </div>
      <Button asChild size="sm">
        <Link to="/jobs/new">
          <PlusCircle size={14} aria-hidden="true" />
          New Job
        </Link>
      </Button>
    </div>
  )
}

export function EmptyFiltered({ onClearFilters }: { onClearFilters: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 px-4 py-16 text-center">
      <EmptyIcon icon={SearchX} />
      <div className="space-y-1">
        <p className="text-sm font-medium text-foreground">No jobs match the current filters</p>
        <p className="text-sm text-muted-foreground">
          Clear your filters or adjust the search.
        </p>
      </div>
      <Button size="sm" variant="outline" onClick={onClearFilters}>
        Clear filters
      </Button>
    </div>
  )
}
