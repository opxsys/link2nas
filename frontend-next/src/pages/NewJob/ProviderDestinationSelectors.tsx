import { cn } from '@/lib/utils'
import type { MockProvider, MockDestination } from './newJob.types'

interface ProviderDestinationSelectorsProps {
  providers: MockProvider[]
  destinations: MockDestination[]
  providerId: string
  destinationId: string
  linksOnly: boolean
  onProviderChange: (id: string) => void
  onDestinationChange: (id: string) => void
  onLinksOnlyChange: (value: boolean) => void
}

const SELECT_CLASS =
  'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:cursor-not-allowed disabled:opacity-50'

export default function ProviderDestinationSelectors({
  providers,
  destinations,
  providerId,
  destinationId,
  linksOnly,
  onProviderChange,
  onDestinationChange,
  onLinksOnlyChange,
}: ProviderDestinationSelectorsProps) {
  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div>
          <label htmlFor="provider-select" className="mb-1.5 block text-xs font-medium text-foreground">
            Provider
          </label>
          <select
            id="provider-select"
            value={providerId}
            onChange={(e) => onProviderChange(e.target.value)}
            className={SELECT_CLASS}
          >
            {providers.map((p) => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
        </div>

        <div>
          <label
            htmlFor="destination-select"
            className={cn('mb-1.5 block text-xs font-medium', linksOnly ? 'text-muted-foreground' : 'text-foreground')}
          >
            Destination
          </label>
          <select
            id="destination-select"
            value={destinationId}
            onChange={(e) => onDestinationChange(e.target.value)}
            className={SELECT_CLASS}
            disabled={linksOnly}
          >
            {destinations.map((d) => (
              <option key={d.id} value={d.id}>{d.name}</option>
            ))}
          </select>
        </div>
      </div>

      <label className="flex cursor-pointer items-center gap-2.5 text-sm">
        <input
          type="checkbox"
          checked={linksOnly}
          onChange={(e) => onLinksOnlyChange(e.target.checked)}
          className="h-4 w-4 rounded border-input accent-primary"
        />
        <span className="text-foreground">Links only — do not transfer to a destination</span>
      </label>

      {linksOnly && (
        <p className="rounded-md bg-sky-50 px-3 py-2 text-xs text-sky-700 dark:bg-sky-900/20 dark:text-sky-400">
          Job will complete with download links available only. No file transfer will occur.
        </p>
      )}
    </div>
  )
}
