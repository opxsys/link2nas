import { useState, useEffect } from 'react'
import { Navigate, Outlet } from 'react-router-dom'
import { getMe } from '@/api/me'
import { clearToken, getStoredToken } from '@/api/auth'
import { invalidateMe } from '@/lib/useMe'

type AuthState = 'checking' | 'ok' | 'rejected'

export default function ProtectedRoute() {
  const [authState, setAuthState] = useState<AuthState>(() =>
    getStoredToken() ? 'checking' : 'rejected'
  )

  // Validate the stored token by calling /api/v2/me on mount.
  // client.ts already removes the token and dispatches auth-expired on 401;
  // the catch block is a safety net for all other failure cases.
  useEffect(() => {
    if (authState !== 'checking') return

    getMe()
      .then(() => setAuthState('ok'))
      .catch(() => {
        clearToken()
        invalidateMe()
        setAuthState('rejected')
      })
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // Also react to auth-expired events fired by client.ts for any later API call.
  useEffect(() => {
    function onExpired() {
      invalidateMe()
      setAuthState('rejected')
    }
    window.addEventListener('auth-expired', onExpired)
    return () => window.removeEventListener('auth-expired', onExpired)
  }, [])

  if (authState === 'rejected') return <Navigate to="/login" replace />
  if (authState === 'checking') return null
  return <Outlet />
}
