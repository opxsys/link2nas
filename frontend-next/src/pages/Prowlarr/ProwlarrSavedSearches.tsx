import { useState } from 'react'
import type { FormEvent } from 'react'
import { Bookmark, X, Plus } from 'lucide-react'
import { useI18n } from '@/i18n'
import type { SavedSearch } from './prowlarr.types'

interface Props {
  saved: SavedSearch[]
  onLoad: (s: SavedSearch) => void
  onDelete: (id: string) => void
  onSave: (name: string) => void
}

export default function ProwlarrSavedSearches({ saved, onLoad, onDelete, onSave }: Props) {
  const { t } = useI18n()
  const [adding, setAdding] = useState(false)
  const [name, setName] = useState('')

  function handleSave(e: FormEvent) {
    e.preventDefault()
    const n = name.trim()
    if (n) {
      onSave(n)
      setName('')
      setAdding(false)
    }
  }

  function handleCancel() {
    setAdding(false)
    setName('')
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
        <Bookmark size={11} aria-hidden="true" />
        {t('prowlarrSavedLabel')}
      </span>

      {saved.map((s) => (
        <div
          key={s.id}
          className="group inline-flex h-6 items-center gap-0.5 rounded-full border border-border bg-muted/40 pl-2.5 pr-1 text-xs"
        >
          <button
            type="button"
            onClick={() => onLoad(s)}
            className="text-foreground hover:underline"
            title={s.name}
          >
            {s.name}
          </button>
          <button
            type="button"
            onClick={() => onDelete(s.id)}
            title={t('prowlarrDeleteSaved')}
            className="ml-1 rounded p-0.5 text-muted-foreground opacity-0 transition-opacity hover:text-destructive group-hover:opacity-100"
          >
            <X size={10} aria-hidden="true" />
          </button>
        </div>
      ))}

      {adding ? (
        <form onSubmit={handleSave} className="inline-flex items-center gap-1">
          <input
            autoFocus
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t('prowlarrSaveSearchName')}
            className="h-6 rounded-md border border-input bg-background px-2 text-xs focus:outline-none focus:ring-1 focus:ring-ring"
          />
          <button
            type="submit"
            disabled={!name.trim()}
            className="h-6 rounded-md border border-primary bg-primary/10 px-2 text-xs text-primary disabled:opacity-50 hover:bg-primary/20"
          >
            {t('prowlarrSaveSearchConfirm')}
          </button>
          <button
            type="button"
            onClick={handleCancel}
            className="h-6 rounded-md border border-border px-2 text-xs text-muted-foreground hover:text-foreground"
          >
            {t('cancel')}
          </button>
        </form>
      ) : (
        <button
          type="button"
          onClick={() => setAdding(true)}
          className="inline-flex h-6 items-center gap-1 rounded-full border border-dashed border-border px-2 text-xs text-muted-foreground hover:border-primary hover:text-primary"
        >
          <Plus size={10} aria-hidden="true" />
          {t('prowlarrSaveSearchBtn')}
        </button>
      )}
    </div>
  )
}
