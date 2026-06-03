import { useState, useEffect, useCallback, useMemo } from 'react'
import {
  listJobs, getJob, deleteJob as deleteJobApi,
  startJob, cancelJob, restartJob,
  sendToDestination, resendToDestination,
} from '@/api/jobs'
import { ApiError } from '@/api/client'
import { filterJobs, getUniqueProviders, getUniqueDestinations } from './jobs.utils'
import type { RealJob } from '@/api/jobs'
import type { JobsFilters } from './jobs.types'

const INITIAL_FILTERS: JobsFilters = { search: '', status: '', provider: '', destination: '' }

export function useJobsState() {
  const [jobs, setJobs] = useState<RealJob[]>([])
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null)
  const [selectedJob, setSelectedJob] = useState<RealJob | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filters, setFilters] = useState<JobsFilters>(INITIAL_FILTERS)
  const [actionPending, setActionPending] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [deletePendingId, setDeletePendingId] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await listJobs(filters.status || undefined)
      setJobs(data)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load jobs.')
    } finally {
      setLoading(false)
    }
  }, [filters.status])

  useEffect(() => { load() }, [load])

  const filteredJobs = useMemo(() => filterJobs(jobs, filters), [jobs, filters])
  const providers = useMemo(() => getUniqueProviders(jobs), [jobs])
  const destinations = useMemo(() => getUniqueDestinations(jobs), [jobs])

  async function selectJob(id: string) {
    if (selectedJobId === id) { setSelectedJobId(null); setSelectedJob(null); return }
    setSelectedJobId(id)
    setActionError(null)
    // Immediate feedback from list
    setSelectedJob(jobs.find(j => j.id === id) ?? null)
    try {
      const detail = await getJob(id)
      setSelectedJob(detail)
    } catch {
      // keep list version
    }
  }

  function clearSelection() { setSelectedJobId(null); setSelectedJob(null) }

  async function performAction(action: string, jobId: string) {
    setActionPending(jobId)
    setActionError(null)
    try {
      let updated: RealJob
      switch (action) {
        case 'start':                updated = await startJob(jobId);              break
        case 'cancel':               updated = await cancelJob(jobId);             break
        case 'restart':              updated = await restartJob(jobId);            break
        case 'send_to_destination':  updated = await sendToDestination(jobId);     break
        case 'resend':               updated = await resendToDestination(jobId);   break
        default: throw new Error(`Unsupported action: ${action}`)
      }
      setJobs(prev => prev.map(j => j.id === jobId ? updated : j))
      if (selectedJobId === jobId) setSelectedJob(updated)
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
      await deleteJobApi(jobId)
      setJobs(prev => prev.filter(j => j.id !== jobId))
      if (selectedJobId === jobId) { setSelectedJobId(null); setSelectedJob(null) }
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

  return {
    jobs, filteredJobs, loading, error,
    selectedJobId, selectedJob, selectJob, clearSelection,
    filters, setFilter, providers, destinations,
    actionPending, actionError, clearActionError: () => setActionError(null),
    performAction,
    deletePendingId, setDeletePendingId, confirmDelete,
    refresh: load,
  }
}
