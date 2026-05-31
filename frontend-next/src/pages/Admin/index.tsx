import PageHeader from '@/components/layout/PageHeader'
import { useAdminMockState } from './useAdminMockState'
import AdminNav from './AdminNav'
import AdminOverview from './AdminOverview'
import AdminUsers from './AdminUsers'
import AdminAnnouncements from './AdminAnnouncements'
import AdminSmtp from './AdminSmtp'
import AdminSecurity from './AdminSecurity'
import AdminRuntime from './AdminRuntime'
import AdminCleanup from './AdminCleanup'
import AdminSystemEvents from './AdminSystemEvents'
import AdminMaintenance from './AdminMaintenance'
import AdminGeneral from './AdminGeneral'
import AdminTimeouts from './AdminTimeouts'

export default function Admin() {
  const { activeSection, setActiveSection, smtpTestStatus, runSmtpTest, cleanupStatus, runCleanup } =
    useAdminMockState()

  return (
    <>
      <PageHeader title="Admin" description="User management and system administration." />
      <div className="flex flex-col gap-6 lg:flex-row lg:items-start">
        <AdminNav activeSection={activeSection} onSelect={setActiveSection} />
        <div className="min-w-0 flex-1">
          {activeSection === 'overview'      && <AdminOverview />}
          {activeSection === 'users'         && <AdminUsers />}
          {activeSection === 'announcements' && <AdminAnnouncements />}
          {activeSection === 'smtp'          && <AdminSmtp testStatus={smtpTestStatus} onTest={runSmtpTest} />}
          {activeSection === 'security'      && <AdminSecurity />}
          {activeSection === 'runtime'       && <AdminRuntime />}
          {activeSection === 'cleanup'       && <AdminCleanup cleanupStatus={cleanupStatus} onRun={runCleanup} />}
          {activeSection === 'system-events' && <AdminSystemEvents />}
          {activeSection === 'maintenance'   && <AdminMaintenance />}
          {activeSection === 'general'       && <AdminGeneral />}
          {activeSection === 'timeouts'      && <AdminTimeouts />}
        </div>
      </div>
    </>
  )
}
