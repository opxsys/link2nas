import { Loader2, XCircle, X } from 'lucide-react'
import type { EmailTemplatePreview } from '@/api/admin-email-templates'

interface Props {
  preview: EmailTemplatePreview | null
  loading: boolean
  error: string | null
  onDismiss: () => void
}

export default function AdminEmailTemplatePreview({ preview, loading, error, onDismiss }: Props) {
  return (
    <div className="rounded-lg border border-border bg-card shadow-sm">
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <h3 className="text-sm font-semibold text-foreground">Preview</h3>
        <button
          type="button"
          onClick={onDismiss}
          className="rounded hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
          aria-label="Close preview"
        >
          <X size={14} aria-hidden="true" />
        </button>
      </div>

      <div className="flex flex-col gap-3 p-4">
        {loading && (
          <div className="flex items-center gap-2 py-4 text-sm text-muted-foreground">
            <Loader2 size={14} className="animate-spin" aria-hidden="true" />
            Generating preview…
          </div>
        )}

        {error && (
          <div className="flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
            <XCircle size={14} className="shrink-0" aria-hidden="true" />
            <span>{error}</span>
          </div>
        )}

        {!loading && preview && (
          <>
            <div>
              <p className="mb-1 text-xs font-medium text-foreground">Subject</p>
              <p className="break-words rounded-md border border-border bg-muted/30 px-3 py-2 text-sm text-foreground">
                {preview.subject}
              </p>
            </div>

            <div>
              <p className="mb-1 text-xs font-medium text-foreground">Body</p>
              <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-md border border-border bg-muted/30 px-3 py-2 font-mono text-xs text-foreground">
                {preview.body}
              </pre>
            </div>

            {Object.keys(preview.sample_values).length > 0 && (
              <div>
                <p className="mb-1.5 text-xs font-medium text-foreground">Sample values used</p>
                <div className="flex flex-col gap-1">
                  {Object.entries(preview.sample_values).map(([k, v]) => (
                    <div key={k} className="flex gap-2 text-xs text-muted-foreground">
                      <code className="shrink-0 font-mono text-foreground">{`{${k}}`}</code>
                      <span className="truncate">{v}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
