import { Search } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useI18n } from '@/i18n'
import type { TranslationKey } from '@/i18n'

export type FilterChip = 'all' | 'active' | 'disabled' | 'super_admin' | 'unverified' | 'expired'

interface ChipDef { key: FilterChip; labelKey: TranslationKey }

const CHIPS: ChipDef[] = [
  { key: 'all',        labelKey: 'adminFilterAll'        },
  { key: 'active',     labelKey: 'badgeActive'           },
  { key: 'disabled',   labelKey: 'badgeDisabled'         },
  { key: 'super_admin', labelKey: 'adminFilterSuperAdmin' },
  { key: 'unverified', labelKey: 'adminFilterUnverified' },
  { key: 'expired',    labelKey: 'badgeExpired'          },
]

interface Props {
  search: string
  filter: FilterChip
  onSearch: (q: string) => void
  onFilter: (f: FilterChip) => void
}

export default function AdminUsersFilter({ search, filter, onSearch, onFilter }: Props) {
  const { t } = useI18n()
  return (
    <div className="mb-4 flex flex-wrap items-center gap-3">
      <div className="relative min-w-48 flex-1">
        <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
        <input
          type="text"
          value={search}
          onChange={(e) => onSearch(e.target.value)}
          placeholder={t('adminSearchUsersPlaceholder')}
          className="h-8 w-full rounded-md border border-input bg-background pl-8 pr-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
        />
      </div>
      <div className="flex flex-wrap gap-1.5">
        {CHIPS.map(({ key, labelKey }) => (
          <Button
            key={key}
            size="sm"
            variant={filter === key ? 'default' : 'outline'}
            className="h-7 text-xs"
            onClick={() => onFilter(key)}
          >
            {t(labelKey)}
          </Button>
        ))}
      </div>
    </div>
  )
}
