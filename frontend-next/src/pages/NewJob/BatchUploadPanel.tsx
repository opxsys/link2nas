import { useRef } from 'react'
import { Upload } from 'lucide-react'

interface BatchUploadPanelProps {
  value: string
  onChange: (value: string) => void
}

export default function BatchUploadPanel({ value, onChange }: BatchUploadPanelProps) {
  const fileInputRef = useRef<HTMLInputElement>(null)
  const lineCount = value.trim() ? value.trim().split('\n').filter(Boolean).length : 0

  return (
    <div className="flex flex-col gap-4">
      <div>
        <label htmlFor="batch-links-input" className="mb-1.5 block text-xs font-medium text-foreground">
          Paste links
        </label>
        <textarea
          id="batch-links-input"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder="Paste multiple magnet links or URLs, one per line…"
          rows={8}
          spellCheck={false}
          className="w-full resize-y rounded-md border border-input bg-background px-3 py-2 font-mono text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
        />
        {lineCount > 0 && (
          <p className="mt-1.5 text-xs text-muted-foreground">
            {lineCount} link{lineCount !== 1 ? 's' : ''} ready to submit
          </p>
        )}
      </div>

      <div className="flex items-center gap-3">
        <div className="h-px flex-1 bg-border" />
        <span className="text-xs text-muted-foreground">or upload a text file</span>
        <div className="h-px flex-1 bg-border" />
      </div>

      <input
        ref={fileInputRef}
        type="file"
        accept=".txt"
        className="sr-only"
        onChange={() => { /* file processing not yet supported */ }}
        aria-label="Select a .txt file with links"
      />
      <button
        onClick={() => fileInputRef.current?.click()}
        className="flex items-center justify-center gap-2 rounded-md border border-dashed border-border py-4 text-sm text-muted-foreground transition-colors hover:border-primary/50 hover:bg-muted/30 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <Upload size={15} aria-hidden="true" />
        Upload .txt file with links
      </button>
    </div>
  )
}
