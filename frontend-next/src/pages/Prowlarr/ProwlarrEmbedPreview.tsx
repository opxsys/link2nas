import { Monitor, ExternalLink } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import type { ProwlarrOpenMode } from './prowlarr.types'

interface Props {
  url: string
  openMode: ProwlarrOpenMode
}

export default function ProwlarrEmbedPreview({ url, openMode }: Props) {
  if (openMode === 'newtab') {
    return (
      <SectionCard title="Prowlarr Preview">
        <div className="flex flex-col items-center justify-center gap-3 py-10 text-center">
          <ExternalLink size={24} className="text-muted-foreground" aria-hidden="true" />
          <p className="text-sm text-muted-foreground">Open mode is set to <strong>new tab</strong>.</p>
          <a
            href="#"
            onClick={(e) => e.preventDefault()}
            className="inline-flex items-center gap-1.5 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground hover:bg-muted"
          >
            <ExternalLink size={14} aria-hidden="true" />
            Open Prowlarr ({url})
          </a>
          <p className="text-xs text-muted-foreground">
            Mock only — no real navigation.
          </p>
        </div>
      </SectionCard>
    )
  }

  return (
    <SectionCard title="Prowlarr Preview">
      <div className="flex flex-col items-center justify-center gap-3 rounded-md border border-dashed border-border bg-muted/30 py-16 text-center">
        <Monitor size={28} className="text-muted-foreground" aria-hidden="true" />
        <p className="text-sm font-medium text-foreground">Iframe preview</p>
        <p className="max-w-sm text-xs text-muted-foreground">
          Prowlarr will be embedded here at <strong>{url}</strong>.
          The iframe loads your existing browser session — no credentials are stored by Link2NAS.
        </p>
        <p className="text-xs text-muted-foreground/60">
          Preview disabled in mock mode.
        </p>
      </div>
    </SectionCard>
  )
}
