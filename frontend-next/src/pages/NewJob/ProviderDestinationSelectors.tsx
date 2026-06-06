import { cn } from '@/lib/utils'
import { useI18n } from '@/i18n'
import type { ProviderConfig } from '@/api/provider-configs'
import type { DestinationConfig } from '@/api/destination-configs'

interface ProviderDestinationSelectorsProps {
  providers: ProviderConfig[]
  destinations: DestinationConfig[]
  providerId: string
  destinationId: string
  linksOnly: boolean
  onProviderChange: (id: string) => void
  onDestinationChange: (id: string) => void
  onLinksOnlyChange: (value: boolean) => void
}

const SELECT_CLASS =
  'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:cursor-not-allowed disabled:opacity-50'

function providerLabel(provider: ProviderConfig): string {
  return provider.name || provider.provider_type || provider.id
}

function destinationLabel(destination: DestinationConfig): string {
  return destination.name || destination.destination_type || destination.id
}

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
  const { t } = useI18n()
  const noDestination = destinations.length === 0

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div>
          <label htmlFor="provider-select" className="mb-1.5 block text-xs font-medium text-foreground">
            {t('colProvider')}
          </label>
          <select
            id="provider-select"
            value={providerId}
            onChange={(e) => onProviderChange(e.target.value)}
            className={SELECT_CLASS}
            disabled={providers.length === 0}
          >
            {providers.length === 0 ? (
              <option value="">{t('noActiveProvider')}</option>
            ) : (
              providers.map((p) => (
                <option key={p.id} value={p.id}>{providerLabel(p)}</option>
              ))
            )}
          </select>
        </div>

        <div>
          <label
            htmlFor="destination-select"
            className={cn('mb-1.5 block text-xs font-medium', linksOnly ? 'text-muted-foreground' : 'text-foreground')}
          >
            {t('colDestination')}
          </label>
          <select
            id="destination-select"
            value={destinationId}
            onChange={(e) => onDestinationChange(e.target.value)}
            className={SELECT_CLASS}
            disabled={linksOnly || noDestination}
          >
            {noDestination ? (
              <option value="">{t('noActiveDestination')}</option>
            ) : (
              destinations.map((d) => (
                <option key={d.id} value={d.id}>{destinationLabel(d)}</option>
              ))
            )}
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
        <span className="text-foreground">{t('linksOnlyLabel')}</span>
      </label>

      {(linksOnly || noDestination) && (
        <p className="rounded-md bg-sky-50 px-3 py-2 text-xs text-sky-700 dark:bg-sky-900/20 dark:text-sky-400">
          {t('linksOnlyHint')}
        </p>
      )}
    </div>
  )
}
