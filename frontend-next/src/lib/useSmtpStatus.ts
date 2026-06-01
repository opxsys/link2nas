import { useState, useEffect } from 'react'
import { getSmtpSettings } from '@/api/admin-smtp'

// Module-level cache — one fetch per session across all consumers.
let cached: boolean | null = null
let pending: Promise<boolean> | null = null

function fetchOnce(): Promise<boolean> {
  if (pending === null) {
    pending = getSmtpSettings()
      .then((s) => {
        cached = s.enabled && s.host.trim() !== ''
        return cached
      })
      .catch(() => {
        cached = false
        return false
      })
  }
  return pending
}

/** Call after successfully saving SMTP settings so the next consumer re-fetches. */
export function invalidateSmtpStatus(): void {
  cached = null
  pending = null
}

/**
 * Returns whether SMTP is configured and enabled.
 * Fails closed: returns false while loading and on any error.
 * All consumers share one fetch per session.
 */
export function useSmtpStatus(): { smtpAvailable: boolean; smtpLoading: boolean } {
  const [available, setAvailable] = useState<boolean>(cached ?? false)
  const [loading, setLoading] = useState<boolean>(cached === null)

  useEffect(() => {
    if (cached !== null) {
      setAvailable(cached)
      setLoading(false)
      return
    }
    fetchOnce().then((v) => {
      setAvailable(v)
      setLoading(false)
    })
  }, [])

  return { smtpAvailable: available, smtpLoading: loading }
}
