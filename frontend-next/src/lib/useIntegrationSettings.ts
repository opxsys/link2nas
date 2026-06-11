import { useState, useEffect } from 'react'
import { getIntegrationSettings } from '@/api/integration-settings'
import type { IntegrationSettings } from '@/api/integration-settings'

export type { IntegrationSettings }

// Module-level cache — shared across all hook instances, one fetch per session.
let cache: IntegrationSettings | null = null
let pending: Promise<IntegrationSettings> | null = null

const REFETCH_EVENT = 'integration-settings-changed'

function fetchOnce(): Promise<IntegrationSettings> {
  if (pending === null) {
    pending = getIntegrationSettings()
      .then((data) => { cache = data; return data })
      .catch((err) => { pending = null; throw err })
  }
  return pending
}

/** Call after a successful PUT to immediately re-sync all consumers. */
export function invalidateIntegrationSettings(): void {
  cache = null
  pending = null
  window.dispatchEvent(new CustomEvent(REFETCH_EVENT))
}

export function isProwlarrAvailable(s: IntegrationSettings | null): boolean {
  // Native search takes priority; fall back to old iframe/new-tab integration.
  if (!s) return false
  return s.native_search_available || Boolean(s.prowlarr_enabled && s.prowlarr_url.trim() !== '')
}

/**
 * Resolve the user's configured home_page preference to a routable path.
 * Falls back to /dashboard when Prowlarr is disabled or the page is unknown.
 */
export function resolveHomePath(settings: IntegrationSettings | null): string {
  const page = settings?.home_page || 'dashboard'
  if (page === 'jobs') return '/jobs'
  if (page === 'prowlarr' && isProwlarrAvailable(settings)) return '/prowlarr'
  return '/dashboard'
}

/**
 * Fetches integration settings once per session, shared across Sidebar,
 * Prowlarr page, and any other consumer. Refetches when Settings saves.
 */
export function useIntegrationSettings(): { settings: IntegrationSettings | null; loading: boolean } {
  const [settings, setSettings] = useState<IntegrationSettings | null>(cache)
  const [loading, setLoading] = useState<boolean>(cache === null)

  useEffect(() => {
    function doFetch() {
      setLoading(true)
      fetchOnce()
        .then((data) => { setSettings(data); setLoading(false) })
        .catch(() => setLoading(false))
    }

    if (cache !== null) {
      setSettings(cache)
      setLoading(false)
    } else {
      doFetch()
    }

    window.addEventListener(REFETCH_EVENT, doFetch)
    return () => window.removeEventListener(REFETCH_EVENT, doFetch)
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  return { settings, loading }
}
