import { useState, useEffect } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import { Loader2, ShieldOff } from 'lucide-react'
import PageHeader from '@/components/layout/PageHeader'
import { Button } from '@/components/ui/button'
import { getMe } from '@/api/me'
import AdminNav from './AdminNav'
import AdminOverview from './AdminOverview'
import AdminUsers from './AdminUsers'
import AdminAnnouncements from './AdminAnnouncements'
import AdminEmails from './AdminEmails'
import AdminSecurity from './AdminSecurity'
import AdminRuntime from './AdminRuntime'
import AdminCleanup from './AdminCleanup'
import AdminSystemEvents from './AdminSystemEvents'
import AdminMaintenance from './AdminMaintenance'
import AdminGeneral from './AdminGeneral'
import AdminTimeouts from './AdminTimeouts'
import type { AdminSection } from './admin.types'

const VALID_SECTIONS: AdminSection[] = [
  'overview', 'general', 'users', 'announcements', 'emails',
  'security', 'timeouts', 'runtime', 'cleanup', 'system-events', 'maintenance',
]

function toSection(raw: string | null): AdminSection {
  return VALID_SECTIONS.includes(raw as AdminSection) ? (raw as AdminSection) : 'overview'
}

type AuthState = 'loading' | 'allowed' | 'denied'

export default function Admin() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()

  const initialSection = toSection(searchParams.get('section'))
  const initialAction = searchParams.get('action') ?? ''

  const [authState, setAuthState] = useState<AuthState>('loading')
  const [activeSection, setActiveSection] = useState<AdminSection>(initialSection)

  useEffect(() => {
    getMe()
      .then((me) => setAuthState(me.role === 'super_admin' ? 'allowed' : 'denied'))
      .catch(() => setAuthState('denied'))
  }, [])

  if (authState === 'loading') {
    return (
      <div className="flex items-center gap-2 py-16 text-sm text-muted-foreground">
        <Loader2 size={16} className="animate-spin" aria-hidden="true" />
        Verifying access…
      </div>
    )
  }

  if (authState === 'denied') {
    return (
      <div className="flex flex-col items-center gap-4 py-20 text-center">
        <ShieldOff size={36} className="text-muted-foreground" aria-hidden="true" />
        <div>
          <p className="text-base font-medium text-foreground">Access denied</p>
          <p className="mt-1 text-sm text-muted-foreground">
            This section is restricted to super administrators.
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={() => navigate('/announcements')}>
          Back to Announcements
        </Button>
      </div>
    )
  }

  return (
    <>
      <PageHeader title="Admin" description="User management and system administration." />
      <div className="flex flex-col gap-6 lg:flex-row lg:items-start">
        <AdminNav activeSection={activeSection} onSelect={setActiveSection} />
        <div className="min-w-0 flex-1">
          {activeSection === 'overview'      && <AdminOverview />}
          {activeSection === 'users'         && <AdminUsers />}
          {activeSection === 'announcements' && (
            <AdminAnnouncements
              openCreate={initialSection === 'announcements' && initialAction === 'create'}
            />
          )}
          {activeSection === 'emails'        && <AdminEmails />}
          {activeSection === 'security'      && <AdminSecurity />}
          {activeSection === 'runtime'       && <AdminRuntime />}
          {activeSection === 'cleanup'       && <AdminCleanup />}
          {activeSection === 'system-events' && <AdminSystemEvents />}
          {activeSection === 'maintenance'   && <AdminMaintenance />}
          {activeSection === 'general'       && <AdminGeneral />}
          {activeSection === 'timeouts'      && <AdminTimeouts />}
        </div>
      </div>
    </>
  )
}
