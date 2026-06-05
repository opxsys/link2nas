import { useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ArrowLeft, Loader2, AlertCircle } from 'lucide-react'
import PageHeader from '@/components/layout/PageHeader'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { useNewJobState } from './useNewJobState'
import NewJobTabs from './NewJobTabs'
import MagnetLinksForm from './MagnetLinksForm'
import TorrentUploadPanel from './TorrentUploadPanel'
import ProviderDestinationSelectors from './ProviderDestinationSelectors'
import AdvancedOptions from './AdvancedOptions'
import CreationResultPanel from './CreationResultPanel'

export default function NewJob() {
  const state = useNewJobState()
  const navigate = useNavigate()

  const noActiveProvider = !state.configsLoading && !state.configsError && state.providers.length === 0

  useEffect(() => {
    if (noActiveProvider) {
      navigate('/jobs', { replace: true, state: { notice: 'no-active-provider' } })
    }
  }, [noActiveProvider, navigate])

  // Show a neutral loader while: configs are loading, or redirect is pending (prevents form flash)
  if (state.configsLoading || noActiveProvider) {
    return (
      <>
        <PageHeader
          title="New Job"
          description="Submit magnet links, direct URLs, or .torrent files."
          actions={
            <Button variant="outline" size="sm" asChild>
              <Link to="/jobs"><ArrowLeft size={13} className="mr-1.5" />Back to Jobs</Link>
            </Button>
          }
        />
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 size={16} className="animate-spin" aria-hidden="true" />
          Loading…
        </div>
      </>
    )
  }

  return (
    <>
      <PageHeader
        title="New Job"
        description="Submit magnet links, direct URLs, or .torrent files."
        actions={
          <Button variant="outline" size="sm" asChild>
            <Link to="/jobs"><ArrowLeft size={13} className="mr-1.5" />Back to Jobs</Link>
          </Button>
        }
      />

      <div className="flex max-w-3xl flex-col gap-4">
        <SectionCard title="Submit" bodyClassName="p-0">
          <NewJobTabs activeTab={state.activeTab} onTabChange={state.setActiveTab} />

          <div className="p-5">
            {state.activeTab === 'magnet' && (
              <MagnetLinksForm value={state.magnetLinks} onChange={state.setMagnetLinks} />
            )}
            {state.activeTab === 'torrent' && (
              <TorrentUploadPanel
                files={state.torrentFiles}
                onFiles={state.handleTorrentFiles}
              />
            )}
          </div>

          <div className="border-t border-border p-5">
            {state.configsLoading ? (
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Loader2 size={14} className="animate-spin" /> Loading providers…
              </div>
            ) : state.configsError ? (
              <div className="flex items-start gap-2 text-sm text-destructive">
                <AlertCircle size={14} className="mt-0.5 shrink-0" />{state.configsError}
              </div>
            ) : state.providers.length === 0 ? (
              <div className="rounded-md border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-300">
                No active provider configured. Go to <Link to="/settings" className="underline">Settings → Providers</Link> to add one before creating jobs.
              </div>
            ) : (
              <ProviderDestinationSelectors
                providers={state.providers}
                destinations={state.destinations}
                providerId={state.providerId}
                destinationId={state.destinationId}
                linksOnly={state.linksOnly}
                onProviderChange={state.setProviderId}
                onDestinationChange={state.setDestinationId}
                onLinksOnlyChange={state.setLinksOnly}
              />
            )}
          </div>

          <div className="border-t border-border p-5">
            <AdvancedOptions
              open={state.advancedOpen}
              onToggle={() => state.setAdvancedOpen(p => !p)}
            />
          </div>

          <div className="flex items-center justify-between border-t border-border px-5 py-4">
            {state.submitting && (
              <span className="flex items-center gap-2 text-sm text-muted-foreground">
                <Loader2 size={14} className="animate-spin" />
                {state.activeTab === 'torrent' && state.torrentFiles.length > 1
                  ? `Uploading ${state.torrentFiles.length} files…`
                  : 'Creating job…'}
              </span>
            )}
            {!state.submitting && <span />}
            <Button onClick={state.handleSubmit} disabled={!state.canSubmit}>
              {state.activeTab === 'torrent' && state.torrentFiles.length > 1
                ? `Create ${state.torrentFiles.length} Jobs`
                : 'Create Job'}
            </Button>
          </div>
        </SectionCard>

        {state.result && (
          <CreationResultPanel result={state.result} onDismiss={state.dismissResult} />
        )}
      </div>
    </>
  )
}
