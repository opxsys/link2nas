import { useState, useEffect } from 'react'
import { useLocation, useNavigate, Link } from 'react-router-dom'
import { AlertCircle, Info } from 'lucide-react'
import PageHeader from '@/components/layout/PageHeader'
import { useI18n } from '@/i18n'
import { useJobsState } from './useJobsState'
import JobsToolbar from './JobsToolbar'
import JobsTable from './JobsTable'
import JobDetailsSheet from './JobDetailsSheet'
import JobDeleteModal from './JobDeleteModal'

export default function Jobs() {
  const { t } = useI18n()
  const state = useJobsState()
  const location = useLocation()
  const navigate = useNavigate()
  const [notice, setNotice] = useState<string | null>(null)

  useEffect(() => {
    const ls = (location.state as { notice?: string; selectedJobId?: string } | null)
    const n = ls?.notice ?? null
    const sid = ls?.selectedJobId ?? null
    if (n) setNotice(n)
    if (n || sid) navigate(location.pathname, { replace: true, state: null })
    if (sid) void state.selectJob(sid)
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const deletePendingJob = state.deletePendingId
    ? state.jobs.find(j => j.id === state.deletePendingId) ?? null
    : null

  return (
    <>
      <PageHeader title={t('navJobs')} description={t('jobsDesc')} />

      {notice === 'no-active-provider' && (
        <div className="mb-4 flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-300">
          <Info size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
          <span>
            {t('jobsNoActiveProvider')}{' '}
            <Link to="/settings?section=providers" className="font-medium underline underline-offset-2 hover:no-underline">
              {t('addEnableProvider')}
            </Link>
            {' '}{t('beforeCreatingJobs')}
          </span>
        </div>
      )}

      {state.error && (
        <div className="mb-4 flex items-start gap-2 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
          <AlertCircle size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
          {state.error}
        </div>
      )}

      <div className="flex flex-col gap-4">
        <JobsToolbar
          filters={state.filters}
          providers={state.providers}
          destinations={state.destinations}
          hasActiveProvider={state.hasActiveProvider}
          onFilter={state.setFilter}
          onRefresh={state.refresh}
        />

        <div className="flex flex-col rounded-lg border border-border bg-card shadow-sm lg:flex-row">
          <div className="min-w-0 flex-1 overflow-x-auto">
            <JobsTable
              jobs={state.filteredJobs}
              totalJobs={state.jobs.length}
              hasActiveProvider={state.hasActiveProvider}
              selectedJobId={state.selectedJobId}
              onSelect={state.selectJob}
              onClearFilters={state.clearAllFilters}
              loading={state.loading}
            />
          </div>

          {state.selectedJob && (
            <div className="border-t border-border lg:w-[clamp(480px,34vw,620px)] lg:shrink-0 lg:border-l lg:border-t-0">
              <JobDetailsSheet
                job={state.selectedJob}
                actionPending={state.actionPending}
                actionError={state.actionError}
                onClose={state.clearSelection}
                onAction={state.performAction}
                onDeleteRequest={(id) => state.setDeletePendingId(id)}
                onDismissError={state.clearActionError}
              />
            </div>
          )}
        </div>
      </div>

      {deletePendingJob && (
        <JobDeleteModal
          job={deletePendingJob}
          pending={state.actionPending === deletePendingJob.id}
          onConfirm={() => state.confirmDelete(deletePendingJob.id)}
          onClose={() => state.setDeletePendingId(null)}
        />
      )}
    </>
  )
}
