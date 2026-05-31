import { Routes, Route } from 'react-router-dom'
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
import Maintenance from '@/pages/Maintenance'

export default function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<Dashboard />} />
        <Route path="jobs" element={<Jobs />} />
        <Route path="jobs/new" element={<NewJob />} />
        <Route path="providers" element={<Providers />} />
        <Route path="destinations" element={<Destinations />} />
        <Route path="prowlarr" element={<Prowlarr />} />
        <Route path="notifications" element={<Notifications />} />
        <Route path="settings" element={<Settings />} />
        <Route path="admin" element={<Admin />} />
        <Route path="maintenance" element={<Maintenance />} />
      </Route>
    </Routes>
  )
}
