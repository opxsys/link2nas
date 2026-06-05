import { useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import { Menu } from 'lucide-react'
import AccountMenu from './AccountMenu'
import { getPageTitle } from '@/lib/nav'
import { useAppInfo } from '@/lib/useAppInfo'

interface HeaderProps {
  onOpenMobileNav: () => void
  mobileNavOpen?: boolean
}

export default function Header({ onOpenMobileNav, mobileNavOpen = false }: HeaderProps) {
  const { pathname } = useLocation()
  const { appInfo } = useAppInfo()
  const appName = appInfo.app_name || 'Link2NAS'
  const pageTitle = getPageTitle(pathname, appName)

  useEffect(() => {
    document.title = pageTitle === appName ? appName : `${pageTitle} · ${appName}`
  }, [pageTitle, appName])

  return (
    <header className="flex h-14 shrink-0 items-center gap-4 border-b border-border bg-card px-4">
      {/* Hamburger — mobile only */}
      <button
        onClick={onOpenMobileNav}
        className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring md:hidden"
        aria-label="Open navigation"
        aria-expanded={mobileNavOpen}
        aria-controls="mobile-nav"
      >
        <Menu size={18} aria-hidden="true" />
      </button>

      <h1 className="flex-1 text-sm font-medium text-foreground">{pageTitle}</h1>

      <AccountMenu />
    </header>
  )
}
