import { ChevronDown, ChevronRight } from 'lucide-react'
import { useI18n } from '@/i18n'

interface AdvancedOptionsProps {
  open: boolean
  onToggle: () => void
}

const SELECT_CLASS =
  'h-9 rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring'

export default function AdvancedOptions({ open, onToggle }: AdvancedOptionsProps) {
  const { t } = useI18n()
  return (
    <div>
      <button
        onClick={onToggle}
        aria-expanded={open}
        className="flex items-center gap-2 rounded text-sm font-medium text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        {open
          ? <ChevronDown size={15} aria-hidden="true" />
          : <ChevronRight size={15} aria-hidden="true" />}
        {t('advancedOptions')}
      </button>

      {open && (
        <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div>
            <label htmlFor="priority-select" className="mb-1.5 block text-xs font-medium text-muted-foreground">
              {t('priority')}
            </label>
            <select id="priority-select" className={SELECT_CLASS}>
              <option>{t('priorityNormal')}</option>
              <option>{t('priorityHigh')}</option>
              <option>{t('priorityLow')}</option>
            </select>
          </div>

          <div>
            <label htmlFor="custom-path-input" className="mb-1.5 block text-xs font-medium text-muted-foreground">
              {t('customPathLabel')}
            </label>
            <input
              id="custom-path-input"
              type="text"
              placeholder={t('customPathPlaceholder')}
              disabled
              className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm placeholder:text-muted-foreground disabled:cursor-not-allowed disabled:opacity-50"
            />
          </div>
        </div>
      )}
    </div>
  )
}
