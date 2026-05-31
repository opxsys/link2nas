import { Cloud, FolderOutput, Link } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { MOCK_DEFAULT_CONFIG } from './dashboard.mock'

export default function DashboardDefaultConfig() {
  const { providerName, destinationName, linksOnly } = MOCK_DEFAULT_CONFIG

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
              {providerName ?? (
                <span className="italic text-muted-foreground">Not configured</span>
              )}
            </dd>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground">
            {linksOnly ? (
              <Link size={15} aria-hidden="true" />
            ) : (
              <FolderOutput size={15} aria-hidden="true" />
            )}
          </div>
          <div className="min-w-0">
            <dt className="text-xs text-muted-foreground">Default Destination</dt>
            <dd className="truncate text-sm font-medium text-foreground">
              {linksOnly ? (
                <span className="text-sky-700 dark:text-sky-400">Links only — no destination</span>
              ) : (
                destinationName ?? (
                  <span className="italic text-muted-foreground">Not configured</span>
                )
              )}
            </dd>
          </div>
        </div>
      </dl>
    </SectionCard>
  )
}
