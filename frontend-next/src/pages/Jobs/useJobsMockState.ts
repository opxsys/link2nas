import { useState, useMemo } from 'react'
import { MOCK_JOBS, MOCK_JOB_DETAILS } from './jobs.mock'
import { filterJobs, getUniqueProviders, getUniqueDestinations } from './jobs.utils'
import type { JobDetails, JobsFilters } from './jobs.types'

const INITIAL_FILTERS: JobsFilters = { search: '', status: '', provider: '', destination: '' }

const EMPTY_PROGRESS = {
  percent: null,
  downloadedSize: null,
  speed: null,
  eta: null,
  connections: null,
  provider: null,
}

export function useJobsMockState() {
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null)
  const [filters, setFilters] = useState<JobsFilters>(INITIAL_FILTERS)

  const filteredJobs = useMemo(() => filterJobs(MOCK_JOBS, filters), [filters])

  const selectedJob = useMemo((): JobDetails | null => {
    if (!selectedJobId) return null
    if (MOCK_JOB_DETAILS[selectedJobId]) return MOCK_JOB_DETAILS[selectedJobId]
    const job = MOCK_JOBS.find((j) => j.id === selectedJobId)
    if (!job) return null
    return { ...job, jobPath: null, files: [], progress: EMPTY_PROGRESS }
  }, [selectedJobId])

  const providers = useMemo(() => getUniqueProviders(MOCK_JOBS), [])
  const destinations = useMemo(() => getUniqueDestinations(MOCK_JOBS), [])

  function setFilter<K extends keyof JobsFilters>(key: K, value: JobsFilters[K]) {
    setFilters((prev) => ({ ...prev, [key]: value }))
  }

  function selectJob(id: string) {
    setSelectedJobId((prev) => (prev === id ? null : id))
  }

  function clearSelection() {
    setSelectedJobId(null)
  }

  return {
    filters,
    setFilter,
    filteredJobs,
    selectedJobId,
    selectedJob,
    selectJob,
    clearSelection,
    providers,
    destinations,
  }
}
