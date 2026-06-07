import { useState, useEffect } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import { Loader2, ShieldOff } from 'lucide-react'
import PageHeader from '@/components/layout/PageHeader'
import { Button } from '@/components/ui/button'
import { getMe } from '@/api/me'
import { useI18n } from '@/i18n'
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
import AdminSso from './AdminSso'
import AdminIdentityProxy from './AdminIdentityProxy'
import type { AdminSection } from './admin.types'

const VALID_SECTIONS: AdminSection[] = [
  'overview', 'general', 'users', 'announcements', 'emails',
  'security', 'timeouts', 'runtime', 'cleanup', 'system-events', 'maintenance', 'sso',
  'identity-proxy',
]

function toSection(raw: string | null): AdminSection {
  return VALID_SECTIONS.includes(raw as AdminSection) ? (raw as AdminSection) : 'overview'
}

type AuthState = 'loading' | 'allowed' | 'denied'

export default function Admin() {
  const { t } = useI18n()
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()

  const initialSection = toSection(searchParams.get('section'))
  const initialAction = searchParams.get('action') ?? ''

  const [authState, setAuthState] = useState<AuthState>('loading')
  const [activeSection, setActiveSection] = useState<AdminSection>(initialSection)
  const [singleUserMode, setSingleUserMode] = useState(false)

  useEffect(() => {
    getMe()
      .then((me) => {
        setAuthState(me.role === 'super_admin' ? 'allowed' : 'denied')
        setSingleUserMode(Boolean(me.single_user_mode))
      })
      .catch(() => setAuthState('denied'))
  }, [])

  const SINGLE_USER_HIDDEN: AdminSection[] = ['users', 'announcements', 'sso', 'identity-proxy']

  // Redirect URL-driven hidden sections to overview in single-user mode
  useEffect(() => {
    if (singleUserMode && SINGLE_USER_HIDDEN.includes(activeSection)) {
      setActiveSection('overview')
    }
  }, [singleUserMode, activeSection]) // eslint-disable-line react-hooks/exhaustive-deps

  const hiddenInSingleUser =
    singleUserMode && SINGLE_USER_HIDDEN.includes(activeSection)
  const effectiveSection: AdminSection = hiddenInSingleUser ? 'overview' : activeSection

  if (authState === 'loading') {
    return (
      <div className="flex items-center gap-2 py-16 text-sm text-muted-foreground">
        <Loader2 size={16} className="animate-spin" aria-hidden="true" />
        {t('adminVerifyingAccess')}
      </div>
    )
  }

  if (authState === 'denied') {
    return (
      <div className="flex flex-col items-center gap-4 py-20 text-center">
        <ShieldOff size={36} className="text-muted-foreground" aria-hidden="true" />
        <div>
          <p className="text-base font-medium text-foreground">{t('adminAccessDenied')}</p>
          <p className="mt-1 text-sm text-muted-foreground">{t('adminAccessDeniedDesc')}</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => navigate(singleUserMode ? '/dashboard' : '/announcements')}>
          {singleUserMode ? t('navDashboard') : t('adminBackToAnnouncements')}
        </Button>
      </div>
    )
  }

  return (
    <>
      <PageHeader title={t('navAdmin')} description={t('adminDesc')} />
      <div className="flex flex-col gap-6 lg:flex-row lg:items-start">
        <AdminNav activeSection={effectiveSection} onSelect={setActiveSection} singleUserMode={singleUserMode} />
        <div className="min-w-0 flex-1">
          {effectiveSection === 'overview'      && <AdminOverview singleUserMode={singleUserMode} />}
          {effectiveSection === 'users'         && <AdminUsers />}
          {effectiveSection === 'announcements' && (
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
          {activeSection === 'sso'             && <AdminSso />}
          {activeSection === 'identity-proxy' && <AdminIdentityProxy />}
        </div>
      </div>
    </>
  )
}
