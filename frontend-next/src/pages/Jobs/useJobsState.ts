import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { useI18n } from '@/i18n'
import {
  listJobs, getJob, deleteJob as apiDeleteJob,
  startJob, cancelJob, restartJob, refreshJob,
  selectJobFiles, unrestrictJob, unrestrictJobFile,
  sendToDestination, resendToDestination, cancelLocalDownload,
  cloneWithProvider,
} from '@/api/jobs'
import { listProviderConfigs } from '@/api/provider-configs'
import { ApiError } from '@/api/client'
import { filterJobs, getUniqueProviders, getUniqueDestinations } from './jobs.utils'
import type { RealJob } from '@/api/jobs'
import type { ProviderConfig } from '@/api/provider-configs'
import type { JobsFilters } from './jobs.types'

const INITIAL_FILTERS: JobsFilters = { search: '', status: '', provider: '', destination: '' }

const JOBS_POLL_MS = 5000

const ACTIVE_STATUSES = new Set([
  'created',
  'waiting',
  'queued',
  'starting',
  'running',
  'downloading',
  'downloaded',
  'waiting_files_selection',
  'partially_ready',
  'sending',
])

const ACTIVE_DESTINATION_STATUSES = new Set([
  'queued',
  'sending',
  'downloading',
  'cancel_requested',
])

type JobActionPayload = {
  destination_config_id?: string
  provider_config_id?: string
  file_id?: string | number
}

function normalize(value: unknown): string {
  return String(value ?? '').trim().toLowerCase()
}

function shouldRefreshSelectedJobDetail(
  selectedFromList: RealJob,
  currentSelected: RealJob | null,
): boolean {
  const selectedStatus = normalize(selectedFromList.status)
  const selectedDestinationStatus = normalize(selectedFromList.destination_status)

  return (
    ACTIVE_STATUSES.has(selectedStatus) ||
    ACTIVE_DESTINATION_STATUSES.has(selectedDestinationStatus) ||
    selectedStatus === 'cancelled' ||
    currentSelected?.status !== selectedFromList.status ||
    currentSelected?.progress !== selectedFromList.progress ||
    currentSelected?.destination_status !== selectedFromList.destination_status ||
    currentSelected?.destination_progress !== selectedFromList.destination_progress ||
    currentSelected?.updated_at !== selectedFromList.updated_at
  )
}

export function useJobsState() {
  const { t } = useI18n()
  const [jobs, setJobs] = useState<RealJob[]>([])
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null)
  const [selectedJob, setSelectedJob] = useState<RealJob | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filters, setFilters] = useState<JobsFilters>(INITIAL_FILTERS)
  const [configuredProviders, setConfiguredProviders] = useState<ProviderConfig[] | null>(null)
  const [actionPending, setActionPending] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [deletePendingId, setDeletePendingId] = useState<string | null>(null)

  const selectedJobIdRef = useRef<string | null>(null)
  const selectedJobRef = useRef<RealJob | null>(null)
  const pollingBusyRef = useRef(false)

  useEffect(() => {
    selectedJobIdRef.current = selectedJobId
  }, [selectedJobId])

  useEffect(() => {
    selectedJobRef.current = selectedJob
  }, [selectedJob])

  async function refreshSelectedFromList(list: RealJob[]) {
    const currentSelectedId = selectedJobIdRef.current
    const currentSelected = selectedJobRef.current

    if (!currentSelectedId) return

    const selectedFromList = list.find((job) => job.id === currentSelectedId)

    if (!selectedFromList) {
      selectedJobIdRef.current = null
      selectedJobRef.current = null
      setSelectedJobId(null)
      setSelectedJob(null)
      return
    }

    if (!shouldRefreshSelectedJobDetail(selectedFromList, currentSelected)) {
      if (currentSelected) {
        setSelectedJob(selectedFromList)
        selectedJobRef.current = selectedFromList
      }
      return
    }

    const detail = await getJob(currentSelectedId)

    selectedJobRef.current = detail
    setSelectedJob(detail)
    setJobs((prev) => prev.map((job) => (job.id === detail.id ? detail : job)))
  }

  const load = useCallback(async (options?: { silent?: boolean }) => {
    const silent = options?.silent ?? false

    if (!silent) {
      setLoading(true)
      setError(null)
    }

    try {
      // Fetch providers only on non-silent loads (initial + manual refresh, not polling)
      const [data, provs] = await Promise.all([
        listJobs(filters.status || undefined),
        silent ? Promise.resolve(null) : listProviderConfigs().catch((): ProviderConfig[] => []),
      ])
      setJobs(data)
      if (!silent && provs !== null) setConfiguredProviders(provs)
      await refreshSelectedFromList(data)

      if (!silent) {
        setError(null)
      }
    } catch (err) {
      if (!silent) {
        setError(err instanceof ApiError ? err.message : t('jobsLoadFailed'))
      }
    } finally {
      if (!silent) {
        setLoading(false)
      }
    }
  }, [filters.status])

  useEffect(() => { void load() }, [load])

  useEffect(() => {
    const timer = window.setInterval(() => {
      if (pollingBusyRef.current) return

      pollingBusyRef.current = true

      void load({ silent: true }).finally(() => {
        pollingBusyRef.current = false
      })
    }, JOBS_POLL_MS)

    return () => {
      window.clearInterval(timer)
    }
  }, [load])

  const filteredJobs = useMemo(() => filterJobs(jobs, filters), [jobs, filters])
  const providers    = useMemo(() => getUniqueProviders(jobs), [jobs])
  const destinations = useMemo(() => getUniqueDestinations(jobs), [jobs])

  async function selectJob(id: string) {
    if (selectedJobId === id) {
      selectedJobIdRef.current = null
      selectedJobRef.current = null
      setSelectedJobId(null)
      setSelectedJob(null)
      return
    }

    selectedJobIdRef.current = id
    setSelectedJobId(id)
    setActionError(null)

    const listVersion = jobs.find(j => j.id === id) ?? null
    selectedJobRef.current = listVersion
    setSelectedJob(listVersion)

    try {
      const detail = await getJob(id)
      selectedJobRef.current = detail
      setSelectedJob(detail)
      setJobs(prev => prev.map(j => j.id === id ? detail : j))
    } catch {
      // keep list version
    }
  }

  function clearSelection() {
    selectedJobIdRef.current = null
    selectedJobRef.current = null
    setSelectedJobId(null)
    setSelectedJob(null)
  }

  function updateJob(updated: RealJob) {
    setJobs(prev => prev.map(j => j.id === updated.id ? updated : j))

    if (selectedJobIdRef.current === updated.id) {
      selectedJobRef.current = updated
      setSelectedJob(updated)
    }
  }

  async function performAction(
    action: string,
    jobId: string,
    payload?: JobActionPayload,
  ) {
    setActionPending(jobId)
    setActionError(null)

    try {
      let updated: RealJob

      switch (action) {
        case 'start':
          updated = await startJob(jobId)
          break

        case 'cancel':
          updated = await cancelJob(jobId)
          break

        case 'restart':
          updated = await restartJob(jobId)
          break

        case 'refresh':
          updated = await refreshJob(jobId)
          break

        case 'select_files':
          updated = await selectJobFiles(jobId, 'all')
          break

        case 'unrestrict':
          updated = await unrestrictJob(jobId)
          break

        case 'unrestrict_file':
          if (payload?.file_id === undefined) {
            throw new Error('Missing file id.')
          }
          updated = await unrestrictJobFile(jobId, payload.file_id)
          break

        case 'send_to_destination':
          updated = await sendToDestination(jobId, {
            destination_config_id: payload?.destination_config_id,
          })
          break

        case 'resend':
          updated = await resendToDestination(jobId, {
            destination_config_id: payload?.destination_config_id,
          })
          break

        case 'cancel_local_download':
          updated = await cancelLocalDownload(jobId)
          break

        case 'clone_with_provider': {
          const res = await cloneWithProvider(jobId, {
            provider_config_id: payload?.provider_config_id,
            auto_start: true,
          })

          setJobs(prev => [res.job, ...prev.filter(j => j.id !== res.job.id)])

          selectedJobIdRef.current = res.job.id
          selectedJobRef.current = res.job

          setSelectedJobId(res.job.id)
          setSelectedJob(res.job)
          return
        }

        default:
          throw new Error(`Unsupported action: ${action}`)
      }

      updateJob(updated)
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : `${action} failed.`)
    } finally {
      setActionPending(null)
    }
  }

  async function confirmDelete(jobId: string) {
    setActionPending(jobId)
    setActionError(null)

    try {
      await apiDeleteJob(jobId)

      setJobs(prev => prev.filter(j => j.id !== jobId))

      if (selectedJobIdRef.current === jobId) {
        clearSelection()
      }
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : 'Delete failed.')
    } finally {
      setActionPending(null)
      setDeletePendingId(null)
    }
  }

  function setFilter<K extends keyof JobsFilters>(key: K, value: JobsFilters[K]) {
    setFilters(prev => ({ ...prev, [key]: value }))
  }

  function clearAllFilters() {
    setFilters(INITIAL_FILTERS)
  }

  // null = still loading; true/false = loaded
  const hasActiveProvider: boolean | null = configuredProviders === null
    ? null
    : configuredProviders.some(p => p.is_enabled)

  return {
    jobs, filteredJobs, loading, error,
    selectedJobId, selectedJob, selectJob, clearSelection,
    filters, setFilter, clearAllFilters, providers, destinations,
    hasActiveProvider,
    actionPending, actionError, clearActionError: () => setActionError(null),
    performAction,
    deletePendingId, setDeletePendingId, confirmDelete,
    refresh: load,
  }
}
