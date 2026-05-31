import { AlertCircle } from 'lucide-react'
import { cn } from '@/lib/utils'

interface UnavailableStateProps {
  message?: string
  note?: string
  className?: string
}

export default function UnavailableState({
  message = 'Not available',
  note,
  className,
}: UnavailableStateProps) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center gap-2 py-8 text-center',
        className,
      )}
    >
      <AlertCircle size={20} className="text-muted-foreground" aria-hidden="true" />
      <p className="text-sm text-muted-foreground">{message}</p>
      {note && (
        <p className="max-w-sm text-xs text-muted-foreground/70">{note}</p>
      )}
    </div>
  )
}
