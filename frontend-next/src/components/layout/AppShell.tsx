import { useState, useEffect } from 'react'
import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'
import Header from './Header'
import MobileNav from './MobileNav'
import { getStoredSidebarState, storeSidebarState } from '@/lib/sidebar'
import { TooltipProvider } from '@/components/ui/tooltip'
import { AnnouncementBadgeProvider } from '@/context/AnnouncementBadgeContext'
import { reloadThemePreference } from '@/lib/useTheme'

export default function AppShell() {
  const [collapsed, setCollapsed] = useState<boolean>(getStoredSidebarState)
  const [mobileNavOpen, setMobileNavOpen] = useState(false)

  // Sync theme with backend once on mount; localStorage cache applies first (no flash)
  useEffect(() => { reloadThemePreference() }, [])

  function toggleSidebar() {
    setCollapsed((prev) => {
      const next = !prev
      storeSidebarState(next)
      return next
    })
  }

  return (
    <AnnouncementBadgeProvider>
      <TooltipProvider delayDuration={400}>
        <div className="flex h-screen overflow-hidden bg-background">
          <Sidebar collapsed={collapsed} onToggle={toggleSidebar} />
          <MobileNav open={mobileNavOpen} onClose={() => setMobileNavOpen(false)} />
          <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
            <Header onOpenMobileNav={() => setMobileNavOpen(true)} mobileNavOpen={mobileNavOpen} />
            <main className="flex-1 overflow-y-auto p-6">
              <Outlet />
            </main>
          </div>
        </div>
      </TooltipProvider>
    </AnnouncementBadgeProvider>
  )
}
