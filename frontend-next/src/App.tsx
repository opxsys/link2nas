import { useEffect } from 'react'
import { Routes, Route, useNavigate } from 'react-router-dom'
import AppShell from '@/components/layout/AppShell'
import Dashboard from '@/pages/Dashboard'
import Jobs from '@/pages/Jobs'
import NewJob from '@/pages/NewJob'
import Providers from '@/pages/Providers'
import Destinations from '@/pages/Destinations'
import Prowlarr from '@/pages/Prowlarr'
import Notifications from '@/pages/Notifications'
import Settings from '@/pages/Settings'
import Admin from '@/pages/Admin'
import Announcements from '@/pages/Announcements'
import Maintenance from '@/pages/Maintenance'
import { useIntegrationSettings, isProwlarrAvailable } from '@/lib/useIntegrationSettings'

function HomeRedirect() {
  const { settings, loading } = useIntegrationSettings()
  const navigate = useNavigate()

  useEffect(() => {
    if (loading || !settings) return
    const page = settings.home_page || 'dashboard'
    if (page === 'jobs') {
      navigate('/jobs', { replace: true })
    } else if (page === 'prowlarr' && isProwlarrAvailable(settings)) {
      navigate('/prowlarr', { replace: true })
    }
    // dashboard, control-center (legacy), prowlarr-disabled, or unknown → Dashboard
  }, [settings, loading, navigate])

  return <Dashboard />
}

export default function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<HomeRedirect />} />
        <Route path="jobs" element={<Jobs />} />
        <Route path="jobs/new" element={<NewJob />} />
        <Route path="providers" element={<Providers />} />
        <Route path="destinations" element={<Destinations />} />
        <Route path="prowlarr" element={<Prowlarr />} />
        <Route path="announcements" element={<Announcements />} />
        <Route path="notifications" element={<Notifications />} />
        <Route path="settings" element={<Settings />} />
        <Route path="admin" element={<Admin />} />
        <Route path="maintenance" element={<Maintenance />} />
      </Route>
    </Routes>
  )
}
