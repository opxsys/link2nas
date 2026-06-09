import { useState } from 'react'
import { Search, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useI18n } from '@/i18n'
import type { SearchStatus } from './prowlarr.types'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:cursor-not-allowed disabled:opacity-50'

interface Props {
  onSearch: (query: string) => void
  searchStatus: SearchStatus
}

export default function ProwlarrSearchForm({ onSearch, searchStatus }: Props) {
  const { t } = useI18n()
  const [query, setQuery] = useState('')
  const searching = searchStatus === 'searching'

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const q = query.trim()
    if (q) onSearch(q)
  }

  return (
    <form onSubmit={handleSubmit} className="flex gap-2">
      <input
        type="search"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder={t('prowlarrSearchQueryPlaceholder')}
        disabled={searching}
        aria-label={t('prowlarrSearchQuery')}
        className={INPUT + ' flex-1'}
      />
      <Button type="submit" size="sm" disabled={searching || !query.trim()}>
        {searching
          ? <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />
          : <Search size={13} className="mr-1.5" aria-hidden="true" />}
        {t('prowlarrSearchBtn')}
      </Button>
    </form>
  )
}
