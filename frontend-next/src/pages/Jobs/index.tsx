import { Link } from 'react-router-dom'
import { PlusCircle } from 'lucide-react'
import PageHeader from '@/components/layout/PageHeader'
import { Button } from '@/components/ui/button'
import { useJobsMockState } from './useJobsMockState'
import JobsToolbar from './JobsToolbar'
import JobsTable from './JobsTable'
import JobDetailsSheet from './JobDetailsSheet'

export default function Jobs() {
  const {
    filters,
    setFilter,
    filteredJobs,
    selectedJobId,
    selectedJob,
    selectJob,
    clearSelection,
    providers,
    destinations,
  } = useJobsMockState()

  return (
    <>
      <PageHeader
        title="Jobs"
        description="Manage and monitor your download jobs."
        actions={
          <Button asChild size="sm">
            <Link to="/jobs/new">
              <PlusCircle size={14} aria-hidden="true" />
              New Job
            </Link>
          </Button>
        }
      />

      <div className="flex flex-col gap-4">
        <JobsToolbar
          filters={filters}
          providers={providers}
          destinations={destinations}
          onFilter={setFilter}
        />

        <div className="flex flex-col rounded-lg border border-border bg-card shadow-sm lg:flex-row">
          <div className="min-w-0 flex-1 overflow-x-auto">
            <JobsTable
              jobs={filteredJobs}
              selectedJobId={selectedJobId}
              onSelect={selectJob}
            />
          </div>

          {selectedJob && (
            <div className="border-t border-border lg:w-[440px] lg:shrink-0 lg:border-l lg:border-t-0">
              <JobDetailsSheet job={selectedJob} onClose={clearSelection} />
            </div>
          )}
        </div>
      </div>
    </>
  )
}
