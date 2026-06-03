import { Cloud, FolderOutput, Link } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import type { ProviderConfig } from '@/api/provider-configs'
import type { DestinationConfig } from '@/api/destination-configs'

interface Props {
  providers: ProviderConfig[] | null
  destinations: DestinationConfig[] | null
  loading: boolean
}

function providerDisplayName(providers: ProviderConfig[]): string | null {
  const enabled = providers.filter(p => p.is_enabled)
  return (enabled.find(p => p.is_default) ?? enabled[0])?.name ?? null
}

function destinationDisplayName(destinations: DestinationConfig[]): string | null {
  const enabled = destinations.filter(d => d.is_enabled)
  return (enabled.find(d => d.is_default) ?? enabled[0])?.name ?? null
}

export default function DashboardDefaultConfig({ providers, destinations, loading }: Props) {
  const providerName   = providers   ? providerDisplayName(providers)     : null
  const destinationName = destinations ? destinationDisplayName(destinations) : null
  const linksOnly      = destinations !== null && destinations.filter(d => d.is_enabled).length === 0

  return (
    <SectionCard title="Default Configuration">
      <dl className="space-y-4">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground">
            <Cloud size={15} aria-hidden="true" />
          </div>
          <div className="min-w-0">
            <dt className="text-xs text-muted-foreground">Default Provider</dt>
            <dd className="truncate text-sm font-medium text-foreground">
              {loading ? (
                <span className="italic text-muted-foreground">Loading…</span>
              ) : providerName ? (
                providerName
              ) : (
                <span className="italic text-muted-foreground">Not configured</span>
              )}
            </dd>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground">
            {linksOnly ? <Link size={15} aria-hidden="true" /> : <FolderOutput size={15} aria-hidden="true" />}
          </div>
          <div className="min-w-0">
            <dt className="text-xs text-muted-foreground">Default Destination</dt>
            <dd className="truncate text-sm font-medium text-foreground">
              {loading ? (
                <span className="italic text-muted-foreground">Loading…</span>
              ) : linksOnly ? (
                <span className="text-sky-700 dark:text-sky-400">Links only — no destination</span>
              ) : destinationName ? (
                destinationName
              ) : (
                <span className="italic text-muted-foreground">Not configured</span>
              )}
            </dd>
          </div>
        </div>
      </dl>
    </SectionCard>
  )
}
