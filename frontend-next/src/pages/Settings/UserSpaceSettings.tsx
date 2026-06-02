import { useState, useEffect, useCallback } from 'react'
import { Copy, Check, Trash2, Loader2, AlertCircle, File } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { getPublicSpace } from '@/api/user-space'
import { ApiError } from '@/api/client'
import type { PublicSpace } from '@/api/user-space'
import UserSpaceCleanupModal from './UserSpaceCleanupModal'

function formatBytes(bytes: number): string {
  if (bytes < 1024)            return `${bytes} B`
  if (bytes < 1024 * 1024)    return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 ** 3)      return `${(bytes / 1024 ** 2).toFixed(1)} MB`
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`
}

export default function UserSpaceSettings() {
  const [space, setSpace] = useState<PublicSpace | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [showCleanup, setShowCleanup] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      setSpace(await getPublicSpace())
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load space info')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  async function copyUrl() {
    if (!space?.url) return
    await navigator.clipboard.writeText(space.url)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  if (loading) {
    return (
      <div className="flex items-center gap-2 py-10 text-sm text-muted-foreground">
        <Loader2 size={16} className="animate-spin" aria-hidden="true" />
        Loading space…
      </div>
    )
  }

  if (error || !space) {
    return (
      <div className="flex items-start gap-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
        <AlertCircle size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
        {error ?? 'Space unavailable.'}
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-6">
      <SectionCard
        title="My Space"
        description="Your personal public file space."
        actions={
          space.file_count > 0 ? (
            <Button
              variant="outline" size="sm"
              className="border-destructive/50 text-destructive hover:bg-destructive/10"
              onClick={() => setShowCleanup(true)}
            >
              <Trash2 size={13} aria-hidden="true" /> Clean up
            </Button>
          ) : undefined
        }
      >
        <div className="flex flex-col gap-4">
          <div>
            <p className="mb-1.5 text-xs font-medium text-foreground">Public URL</p>
            <div className="flex items-center gap-2">
              <code className="flex-1 truncate rounded bg-muted px-3 py-2 font-mono text-xs text-foreground">
                {space.url}
              </code>
              <Button variant="outline" size="icon" className="h-8 w-8 shrink-0"
                onClick={copyUrl} aria-label="Copy public URL">
                {copied
                  ? <Check size={13} className="text-green-600 dark:text-green-400" aria-hidden="true" />
                  : <Copy size={13} aria-hidden="true" />}
              </Button>
            </div>
          </div>

          <div className="flex gap-6 text-sm">
            <p>
              <span className="text-muted-foreground">Files: </span>
              <span className="font-medium text-foreground">{space.file_count}</span>
            </p>
            <p>
              <span className="text-muted-foreground">Total size: </span>
              <span className="font-medium text-foreground">{formatBytes(space.total_size_bytes)}</span>
            </p>
          </div>
        </div>
      </SectionCard>

      {space.files.length > 0 && (
        <SectionCard title="Files">
          <ul className="divide-y divide-border">
            {space.files.map((file) => (
              <li key={file.relative_path} className="flex items-center gap-3 py-2.5">
                <File size={13} className="shrink-0 text-muted-foreground" aria-hidden="true" />
                <span className="min-w-0 flex-1 truncate font-mono text-xs text-foreground">
                  {file.relative_path}
                </span>
                <span className="shrink-0 text-xs text-muted-foreground">
                  {formatBytes(file.size_bytes)}
                </span>
              </li>
            ))}
          </ul>
        </SectionCard>
      )}

      {showCleanup && (
        <UserSpaceCleanupModal
          fileCount={space.file_count}
          onClose={() => setShowCleanup(false)}
          onCleaned={load}
        />
      )}
    </div>
  )
}
