import { Search } from 'lucide-react'
import { Button } from '@/components/ui/button'

export type FilterChip = 'all' | 'active' | 'disabled' | 'super_admin' | 'unverified' | 'expired'

const CHIPS: { key: FilterChip; label: string }[] = [
  { key: 'all',        label: 'All'        },
  { key: 'active',     label: 'Active'     },
  { key: 'disabled',   label: 'Disabled'   },
  { key: 'super_admin', label: 'Super admin' },
  { key: 'unverified', label: 'Unverified' },
  { key: 'expired',    label: 'Expired'    },
]

interface Props {
  search: string
  filter: FilterChip
  onSearch: (q: string) => void
  onFilter: (f: FilterChip) => void
}

export default function AdminUsersFilter({ search, filter, onSearch, onFilter }: Props) {
  return (
    <div className="mb-4 flex flex-wrap items-center gap-3">
      <div className="relative min-w-48 flex-1">
        <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
        <input
          type="text"
          value={search}
          onChange={(e) => onSearch(e.target.value)}
          placeholder="Search by email or name…"
          className="h-8 w-full rounded-md border border-input bg-background pl-8 pr-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
        />
      </div>
      <div className="flex flex-wrap gap-1.5">
        {CHIPS.map(({ key, label }) => (
          <Button
            key={key}
            size="sm"
            variant={filter === key ? 'default' : 'outline'}
            className="h-7 text-xs"
            onClick={() => onFilter(key)}
          >
            {label}
          </Button>
        ))}
      </div>
    </div>
  )
}
