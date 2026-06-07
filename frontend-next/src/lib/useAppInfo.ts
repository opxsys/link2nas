import { useState, useEffect } from 'react'
import { getAppInfo, type AppInfo } from '@/api/app-info'

let cache: AppInfo | null = null
let pending: Promise<AppInfo> | null = null

const FALLBACK: AppInfo = {
  app_name: 'Link2NAS',
  app_tagline: '',
  email_sending_available: false,
  oidc_enabled: false,
  oidc_label: '',
}

function fetchOnce(): Promise<AppInfo> {
  if (pending === null) {
    pending = getAppInfo()
      .then((data) => { cache = data; return data })
      .catch((err) => { pending = null; throw err })
  }
  return pending
}

export function invalidateAppInfo(): void {
  cache = null
  pending = null
}

export function useAppInfo(): { appInfo: AppInfo; loading: boolean } {
  const [appInfo, setAppInfo] = useState<AppInfo>(cache ?? FALLBACK)
  const [loading, setLoading] = useState(cache === null)

  useEffect(() => {
    if (cache !== null) {
      setAppInfo(cache)
      setLoading(false)
      return
    }
    fetchOnce()
      .then((data) => { setAppInfo(data); setLoading(false) })
      .catch(() => setLoading(false))
  }, [])

  return { appInfo, loading }
}
