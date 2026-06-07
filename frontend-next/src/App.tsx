import { Routes, Route, Navigate } from 'react-router-dom'
import AppShell from '@/components/layout/AppShell'
import ProtectedRoute from '@/components/auth/ProtectedRoute'
import LoginPage from '@/pages/Auth/LoginPage'
import MagicLoginConfirmPage from '@/pages/Auth/MagicLoginConfirmPage'
import OidcCallbackPage from '@/pages/Auth/OidcCallbackPage'
import ResetPasswordPage from '@/pages/Auth/ResetPasswordPage'
import InvitePage from '@/pages/Auth/InvitePage'
import VerifyEmailPage from '@/pages/Auth/VerifyEmailPage'
import Dashboard from '@/pages/Dashboard'
import Jobs from '@/pages/Jobs'
import NewJob from '@/pages/NewJob'
import Prowlarr from '@/pages/Prowlarr'
import Notifications from '@/pages/Notifications'
import Settings from '@/pages/Settings'
import Admin from '@/pages/Admin'
import Announcements from '@/pages/Announcements'
import Maintenance from '@/pages/Maintenance'
import { useIntegrationSettings, isProwlarrAvailable } from '@/lib/useIntegrationSettings'

// Resolves the user's home_page preference and immediately redirects.
// Renders null while settings load so Dashboard never flashes before a redirect.
function HomeRedirect() {
  const { settings, loading } = useIntegrationSettings()

  if (loading) return null

  const page = settings?.home_page || 'dashboard'
  if (page === 'jobs') return <Navigate to="/jobs" replace />
  if (page === 'prowlarr' && isProwlarrAvailable(settings)) return <Navigate to="/prowlarr" replace />
  return <Navigate to="/dashboard" replace />
}

export default function App() {
  return (
    <Routes>
      {/* Public auth routes — no sidebar */}
      <Route path="login" element={<LoginPage />} />
      <Route path="magic-login" element={<MagicLoginConfirmPage />} />
      <Route path="oidc/callback" element={<OidcCallbackPage />} />
      <Route path="reset-password" element={<ResetPasswordPage />} />
      <Route path="invite" element={<InvitePage />} />
      <Route path="verify-email" element={<VerifyEmailPage />} />

      {/* Protected app routes — redirect to /login if no token */}
      <Route element={<ProtectedRoute />}>
        <Route element={<AppShell />}>
          {/* Index applies the home_page preference then redirects — never stays here */}
          <Route index element={<HomeRedirect />} />
          {/* Dashboard has its own stable route — always accessible from the sidebar */}
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="jobs" element={<Jobs />} />
          <Route path="jobs/new" element={<NewJob />} />
          <Route path="prowlarr" element={<Prowlarr />} />
          <Route path="announcements" element={<Announcements />} />
          <Route path="notifications" element={<Notifications />} />
          <Route path="settings" element={<Settings />} />
          <Route path="admin" element={<Admin />} />
          <Route path="maintenance" element={<Maintenance />} />
        </Route>
      </Route>
    </Routes>
  )
}
