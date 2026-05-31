import { useState } from 'react'
import { Outlet } from 'react-router-dom'
import Sidebar from './Sidebar'
import Header from './Header'
import { getStoredSidebarState, storeSidebarState } from '@/lib/sidebar'

export default function AppShell() {
  const [collapsed, setCollapsed] = useState<boolean>(getStoredSidebarState)

  function toggleSidebar() {
    setCollapsed((prev) => {
      const next = !prev
      storeSidebarState(next)
      return next
    })
  }

  return (
    <div className="flex h-screen overflow-hidden bg-background">
      <Sidebar collapsed={collapsed} onToggle={toggleSidebar} />
      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        <Header />
        <main className="flex-1 overflow-y-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
