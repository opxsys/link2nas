import { ChevronLeft, ChevronRight } from 'lucide-react'
import { useI18n } from '@/i18n'

const PAGE_SIZE_OPTIONS = [10, 25, 50]

interface Props {
  page: number
  pageSize: number
  hasNext: boolean
  totalFiltered?: number
  onPageChange: (page: number) => void
  onPageSizeChange: (size: number) => void
  disabled?: boolean
}

export default function ProwlarrPaginationBar({
  page, pageSize, hasNext, totalFiltered,
  onPageChange, onPageSizeChange,
  disabled,
}: Props) {
  const { t } = useI18n()
  const hasPrev = page > 0
  const currentPage = page + 1
  const totalPages = totalFiltered != null
    ? Math.max(1, Math.ceil(totalFiltered / pageSize))
    : undefined
  const canGoNext = totalPages != null ? currentPage < totalPages : hasNext

  return (
    <div className="flex items-center justify-between border-t border-border bg-muted/20 px-3 py-2">
      <div className="flex items-center gap-1.5">
        <span className="text-xs text-muted-foreground">{t('prowlarrPageSize')}</span>
        <select
          value={pageSize}
          onChange={(e) => onPageSizeChange(Number(e.target.value))}
          disabled={disabled}
          className="h-7 rounded border border-input bg-background px-1.5 text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50"
        >
          {PAGE_SIZE_OPTIONS.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      </div>
      <div className="flex items-center gap-2">
        <span className="text-xs text-muted-foreground tabular-nums">
          {t('prowlarrPageLabel')} {currentPage}
          {totalPages != null ? ` / ${totalPages}` : ''}
        </span>
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={() => onPageChange(page - 1)}
            disabled={!hasPrev || disabled}
            aria-label={t('prowlarrPagePrev')}
            className="inline-flex h-7 items-center gap-1 rounded border border-input bg-background px-2 text-xs text-foreground hover:bg-muted/60 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <ChevronLeft size={12} aria-hidden="true" />
            {t('prowlarrPagePrev')}
          </button>
          <button
            type="button"
            onClick={() => onPageChange(page + 1)}
            disabled={!canGoNext || disabled}
            aria-label={t('prowlarrPageNext')}
            className="inline-flex h-7 items-center gap-1 rounded border border-input bg-background px-2 text-xs text-foreground hover:bg-muted/60 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {t('prowlarrPageNext')}
            <ChevronRight size={12} aria-hidden="true" />
          </button>
        </div>
      </div>
    </div>
  )
}
