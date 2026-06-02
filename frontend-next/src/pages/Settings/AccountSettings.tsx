import { useState, useEffect } from 'react'
import { Loader2, AlertCircle } from 'lucide-react'
import { getMe } from '@/api/me'
import { ApiError } from '@/api/client'
import type { MeProfile } from '@/api/me'
import AccountProfileCard from './AccountProfileCard'
import AccountPasswordCard from './AccountPasswordCard'

export default function AccountSettings() {
  const [me, setMe] = useState<MeProfile | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    getMe()
      .then((data) => { if (!cancelled) setMe(data) })
      .catch((err) => {
        if (!cancelled)
          setError(err instanceof ApiError ? err.message : 'Failed to load account')
      })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [])

  if (loading) {
    return (
      <div className="flex items-center gap-2 py-10 text-sm text-muted-foreground">
        <Loader2 size={16} className="animate-spin" aria-hidden="true" />
        Loading account…
      </div>
    )
  }

  if (error || !me) {
    return (
      <div className="flex items-start gap-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
        <AlertCircle size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
        {error ?? 'Account data unavailable.'}
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-6">
      <AccountProfileCard me={me} onUpdate={setMe} />
      <AccountPasswordCard singleUserMode={me.single_user_mode} />
    </div>
  )
}
