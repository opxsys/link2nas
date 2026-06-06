import { useRef, useState } from 'react'
import { Upload, FileText, X } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useI18n } from '@/i18n'

interface TorrentUploadPanelProps {
  files: File[]
  onFiles: (files: File[]) => void
}

export default function TorrentUploadPanel({ files, onFiles }: TorrentUploadPanelProps) {
  const { t } = useI18n()
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)

  function addFiles(incoming: FileList | null) {
    if (!incoming) return
    const next = Array.from(incoming).filter(f => f.name.endsWith('.torrent'))
    if (!next.length) return
    const existing = new Set(files.map(f => f.name))
    onFiles([...files, ...next.filter(f => !existing.has(f.name))])
  }

  function removeFile(name: string) { onFiles(files.filter(f => f.name !== name)) }
  function onDragOver(e: React.DragEvent) { e.preventDefault(); setDragging(true) }
  function onDragLeave() { setDragging(false) }
  function onDrop(e: React.DragEvent) { e.preventDefault(); setDragging(false); addFiles(e.dataTransfer.files) }

  return (
    <div className="flex flex-col gap-3">
      <input ref={inputRef} type="file" accept=".torrent" multiple className="sr-only"
        onChange={e => { addFiles(e.target.files); e.target.value = '' }}
        aria-label={t('ariaTorrentInput')} />

      <button type="button" onClick={() => inputRef.current?.click()}
        onDragOver={onDragOver} onDragLeave={onDragLeave} onDrop={onDrop}
        className={cn(
          'flex flex-col items-center justify-center gap-3 rounded-md border-2 border-dashed py-10 text-sm transition-colors',
          'text-muted-foreground hover:border-primary/50 hover:bg-muted/30 hover:text-foreground',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
          dragging && 'border-primary bg-primary/5 text-primary',
        )}>
        <Upload size={22} aria-hidden="true" />
        <span>{t('torrentDropPre')} <strong>.torrent</strong> {t('torrentDropPost')}</span>
        <span className="text-xs">{t('torrentDropHint')}</span>
      </button>

      {files.length > 0 && (
        <ul className="flex flex-col gap-1.5">
          {files.map(file => (
            <li key={file.name} className="flex items-center gap-3 rounded-md border border-border bg-muted/30 px-3 py-2">
              <FileText size={15} className="shrink-0 text-primary" aria-hidden="true" />
              <span className="min-w-0 flex-1 truncate text-xs font-medium text-foreground">{file.name}</span>
              <button type="button" onClick={() => removeFile(file.name)}
                className="shrink-0 rounded text-muted-foreground hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                aria-label={`${t('delete')} ${file.name}`}>
                <X size={14} aria-hidden="true" />
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
