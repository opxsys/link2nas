import { ChevronDown, ChevronRight } from 'lucide-react'

interface AdvancedOptionsProps {
  open: boolean
  onToggle: () => void
}

const SELECT_CLASS =
  'h-9 rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring'

export default function AdvancedOptions({ open, onToggle }: AdvancedOptionsProps) {
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
        Advanced options
      </button>

      {open && (
        <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div>
            <label htmlFor="priority-select" className="mb-1.5 block text-xs font-medium text-muted-foreground">
              Priority
            </label>
            <select id="priority-select" className={SELECT_CLASS}>
              <option>Normal</option>
              <option>High</option>
              <option>Low</option>
            </select>
          </div>

          <div>
            <label htmlFor="custom-path-input" className="mb-1.5 block text-xs font-medium text-muted-foreground">
              Custom path override
            </label>
            <input
              id="custom-path-input"
              type="text"
              placeholder="Leave blank to use destination default"
              disabled
              className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm placeholder:text-muted-foreground disabled:cursor-not-allowed disabled:opacity-50"
            />
          </div>
        </div>
      )}
    </div>
  )
}
