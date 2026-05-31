import { useRef } from 'react'
import { Upload, FileText, X } from 'lucide-react'
import { cn } from '@/lib/utils'

interface TorrentUploadPanelProps {
  fileName: string | null
  onFile: (file: File | null) => void
}

export default function TorrentUploadPanel({ fileName, onFile }: TorrentUploadPanelProps) {
  const inputRef = useRef<HTMLInputElement>(null)

  return (
    <div className="flex flex-col gap-3">
      <input
        ref={inputRef}
        type="file"
        accept=".torrent"
        className="sr-only"
        onChange={(e) => onFile(e.target.files?.[0] ?? null)}
        aria-label="Select a .torrent file"
      />

      {fileName ? (
        <div className="flex items-center gap-3 rounded-md border border-border bg-muted/30 px-4 py-3">
          <FileText size={18} className="shrink-0 text-primary" aria-hidden="true" />
          <span className="min-w-0 flex-1 truncate text-sm font-medium text-foreground">
            {fileName}
          </span>
          <button
            onClick={() => onFile(null)}
            className="shrink-0 rounded text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            aria-label="Remove selected torrent file"
          >
            <X size={15} aria-hidden="true" />
          </button>
        </div>
      ) : (
        <button
          onClick={() => inputRef.current?.click()}
          className={cn(
            'flex flex-col items-center justify-center gap-3 rounded-md border-2 border-dashed border-border py-14 text-sm',
            'text-muted-foreground transition-colors hover:border-primary/50 hover:bg-muted/30 hover:text-foreground',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
          )}
        >
          <Upload size={24} aria-hidden="true" />
          <span>
            Click to select a <strong>.torrent</strong> file
          </span>
          <span className="text-xs">Drag and drop not yet supported</span>
        </button>
      )}
    </div>
  )
}
