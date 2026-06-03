import { useLocation } from 'react-router-dom'
import { Menu } from 'lucide-react'
import AccountMenu from './AccountMenu'
import { getPageTitle } from '@/lib/nav'

interface HeaderProps {
  onOpenMobileNav: () => void
}

export default function Header({ onOpenMobileNav }: HeaderProps) {
  const { pathname } = useLocation()

  return (
    <header className="flex h-14 shrink-0 items-center gap-4 border-b border-border bg-card px-4">
      {/* Hamburger — mobile only */}
      <button
        onClick={onOpenMobileNav}
        className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring md:hidden"
        aria-label="Open navigation"
      >
        <Menu size={18} aria-hidden="true" />
      </button>

      <h1 className="flex-1 text-sm font-medium text-foreground">{getPageTitle(pathname)}</h1>

      <AccountMenu />
    </header>
  )
}
