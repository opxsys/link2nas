import { useRef } from 'react'
import { X, CalendarDays } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useI18n } from '@/i18n'

const INPUT_CLS = 'h-9 min-w-0 flex-1 rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const LABEL_CLS = 'mb-1.5 block text-xs font-medium text-foreground'

interface Props {
  id: string
  label: string
  hint?: string
  value: string
  disabled?: boolean
  onChange: (value: string) => void
}

export default function DateTimeField({ id, label, hint, value, disabled, onChange }: Props) {
  const { t } = useI18n()
  const ref = useRef<HTMLInputElement>(null)

  function openPicker() {
    const el = ref.current
    if (!el) return
    try {
      const ep = el as HTMLInputElement & { showPicker?: () => void }
      if (typeof ep.showPicker === 'function') ep.showPicker()
      else el.focus()
    } catch {
      el.focus()
    }
  }

  return (
    <div>
      <label htmlFor={id} className={LABEL_CLS}>
        {label}
        {hint && <span className="ml-1 text-xs text-muted-foreground">{hint}</span>}
      </label>
      <div className="flex gap-1.5">
        <input
          ref={ref}
          id={id}
          type="datetime-local"
          className={INPUT_CLS}
          value={value}
          disabled={disabled}
          onChange={(e) => onChange(e.target.value)}
        />
        <Button type="button" size="icon" variant="outline" className="h-9 w-9 shrink-0"
          disabled={disabled} aria-label={t('ariaOpenDatePicker')} onClick={openPicker}>
          <CalendarDays size={14} aria-hidden="true" />
        </Button>
        {value && (
          <Button type="button" size="icon" variant="outline" className="h-9 w-9 shrink-0"
            disabled={disabled} aria-label={t('ariaClearDate')} onClick={() => onChange('')}>
            <X size={14} aria-hidden="true" />
          </Button>
        )}
      </div>
    </div>
  )
}
