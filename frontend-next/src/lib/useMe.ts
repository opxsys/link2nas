import { useState, useEffect } from 'react'
import { getMe } from '@/api/me'
import type { MeProfile } from '@/api/me'

// Module-level cache shared across all hook instances, one fetch per session.
let cache: MeProfile | null = null
let pending: Promise<MeProfile> | null = null

const REFETCH_EVENT = 'me-profile-changed'

function fetchOnce(): Promise<MeProfile> {
  if (pending === null) {
    pending = getMe()
      .then((data) => { cache = data; return data })
      .catch((err) => { pending = null; throw err })
  }
  return pending
}

/** Call after a successful PATCH /api/v2/me to re-sync all consumers. */
export function invalidateMe(): void {
  cache = null
  pending = null
  window.dispatchEvent(new CustomEvent(REFETCH_EVENT))
}

export function useMe(): { me: MeProfile | null; loading: boolean } {
  const [me, setMe] = useState<MeProfile | null>(cache)
  const [loading, setLoading] = useState(cache === null)

  useEffect(() => {
    function doFetch() {
      setLoading(true)
      fetchOnce()
        .then((data) => { setMe(data); setLoading(false) })
        .catch(() => setLoading(false))
    }

    if (cache !== null) {
      setMe(cache)
      setLoading(false)
    } else {
      doFetch()
    }

    window.addEventListener(REFETCH_EVENT, doFetch)
    return () => window.removeEventListener(REFETCH_EVENT, doFetch)
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  return { me, loading }
}
