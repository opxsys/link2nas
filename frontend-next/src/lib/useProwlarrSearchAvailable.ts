import { useState, useEffect } from 'react'
import { getMeProwlarr } from '@/api/prowlarr'

// Module-level cache — one fetch per session, shared across Sidebar, MobileNav, HomeRedirect.
let cache: boolean | null = null
let pending: Promise<boolean> | null = null
const REFETCH_EVENT = 'prowlarr-search-available-changed'

function fetchOnce(): Promise<boolean> {
  if (pending === null) {
    pending = getMeProwlarr()
      .then((data) => {
        cache = data.search_available
        return data.search_available
      })
      .catch(() => {
        pending = null
        return false
      })
  }
  return pending
}

/** Call after saving Prowlarr settings so the sidebar updates immediately. */
export function invalidateProwlarrSearchAvailable(): void {
  cache = null
  pending = null
  window.dispatchEvent(new CustomEvent(REFETCH_EVENT))
}

/**
 * Returns whether the effective Prowlarr configuration (user or global admin)
 * is active and has a base_url + API key — i.e. the /prowlarr search page is usable.
 */
export function useProwlarrSearchAvailable(): { available: boolean; loading: boolean } {
  const [available, setAvailable] = useState<boolean>(cache ?? false)
  const [loading, setLoading] = useState<boolean>(cache === null)

  useEffect(() => {
    function doFetch() {
      setLoading(true)
      fetchOnce()
        .then((v) => { setAvailable(v); setLoading(false) })
        .catch(() => setLoading(false))
    }

    if (cache !== null) {
      setAvailable(cache)
      setLoading(false)
    } else {
      doFetch()
    }

    window.addEventListener(REFETCH_EVENT, doFetch)
    return () => window.removeEventListener(REFETCH_EVENT, doFetch)
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  return { available, loading }
}
