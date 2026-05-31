import { FolderOutput, Pencil, Trash2, Plus } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { MOCK_DESTINATIONS } from './settings.mock'

export default function DestinationSettings() {
  return (
    <SectionCard
      title="Destinations"
      description="File transfer destinations. Zero active destinations means links-only mode."
      actions={
        <Button variant="outline" size="sm" disabled>
          <Plus size={13} aria-hidden="true" /> Add destination
        </Button>
      }
    >
      <div className="flex flex-col gap-3">
        {MOCK_DESTINATIONS.map((dest) => (
          <div
            key={dest.id}
            className="flex items-center gap-4 rounded-lg border border-border p-4"
          >
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-muted text-foreground">
              <FolderOutput size={18} aria-hidden="true" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-sm font-medium text-foreground">{dest.name}</span>
                <span className="rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground">
                  {dest.typeLabel}
                </span>
                {dest.isActive && (
                  <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-400">
                    Active
                  </span>
                )}
                {dest.isDefault && (
                  <span className="rounded-full bg-primary/10 px-2 py-0.5 text-xs font-medium text-primary">
                    Default
                  </span>
                )}
              </div>
              <p className="mt-0.5 font-mono text-xs text-muted-foreground">{dest.path}</p>
            </div>
            <div className="flex shrink-0 gap-1">
              <Button variant="ghost" size="icon" disabled aria-label={`Edit ${dest.name}`}>
                <Pencil size={14} aria-hidden="true" />
              </Button>
              <Button
                variant="ghost"
                size="icon"
                disabled
                className="text-destructive/50"
                aria-label={`Delete ${dest.name}`}
              >
                <Trash2 size={14} aria-hidden="true" />
              </Button>
            </div>
          </div>
        ))}
        <p className="text-xs text-muted-foreground">
          Destination editing is not yet available in this UI.
        </p>
      </div>
    </SectionCard>
  )
}
