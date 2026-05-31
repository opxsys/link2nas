import { useLocation } from 'react-router-dom'
import { User } from 'lucide-react'
import ThemeSelector from './ThemeSelector'
import { getPageTitle } from '@/lib/nav'

export default function Header() {
  const { pathname } = useLocation()

  return (
    <header className="flex h-14 shrink-0 items-center gap-4 border-b border-border bg-card px-4">
      <h1 className="flex-1 text-sm font-medium text-foreground">{getPageTitle(pathname)}</h1>

      <ThemeSelector />

      {/* User placeholder — auth not wired in first step */}
      <div className="flex select-none items-center gap-2 text-sm text-muted-foreground">
        <User size={16} aria-hidden="true" />
        <span className="hidden sm:inline">Account</span>
      </div>
    </header>
  )
}
