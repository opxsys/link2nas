import { useState, useEffect, useCallback, useRef } from 'react'
import { getControlCenter } from '@/api/system'
import { listJobs } from '@/api/jobs'
import { getMaintenanceStatus } from '@/api/admin-maintenance'
import { listProviderConfigs } from '@/api/provider-configs'
import { listDestinationConfigs } from '@/api/destination-configs'
import type { ControlCenter } from '@/api/system'
import type { RealJob } from '@/api/jobs'
import type { MaintenanceStatus } from '@/pages/Admin/admin.types'
import type { ProviderConfig } from '@/api/provider-configs'
import type { DestinationConfig } from '@/api/destination-configs'

const POLL_MS = 5_000

export interface DashboardState {
  controlCenter: ControlCenter | null
  jobs: RealJob[] | null
  maintenance: MaintenanceStatus | null
  providers: ProviderConfig[] | null
  destinations: DestinationConfig[] | null
  loading: boolean
  error: string | null
  refresh: () => void
}

export function useDashboardData(): DashboardState {
  const [controlCenter, setControlCenter] = useState<ControlCenter | null>(null)
  const [jobs, setJobs] = useState<RealJob[] | null>(null)
  const [maintenance, setMaintenance] = useState<MaintenanceStatus | null>(null)
  const [providers, setProviders] = useState<ProviderConfig[] | null>(null)
  const [destinations, setDestinations] = useState<DestinationConfig[] | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Lightweight poll: only refresh frequently-changing data
  const fetchPolled = useCallback(async () => {
    try {
      const [cc, js] = await Promise.all([getControlCenter(), listJobs()])
      setControlCenter(cc)
      setJobs(js)
    } catch {
      // Silently ignore poll errors; the initial error banner is enough
    }
  }, [])

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [cc, js, maint, provs, dests] = await Promise.all([
        getControlCenter(),
        listJobs(),
        getMaintenanceStatus().catch(() => null),
        listProviderConfigs().catch(() => null),
        listDestinationConfigs().catch(() => null),
      ])
      setControlCenter(cc)
      setJobs(js)
      setMaintenance(maint)
      setProviders(provs)
      setDestinations(dests)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load dashboard')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
    timerRef.current = setInterval(() => { void fetchPolled() }, POLL_MS)
    return () => {
      if (timerRef.current !== null) clearInterval(timerRef.current)
    }
  }, [load, fetchPolled])

  return { controlCenter, jobs, maintenance, providers, destinations, loading, error, refresh: load }
}
