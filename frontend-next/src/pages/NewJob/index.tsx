import PageHeader from '@/components/layout/PageHeader'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { useNewJobState } from './useNewJobState'
import NewJobTabs from './NewJobTabs'
import MagnetLinksForm from './MagnetLinksForm'
import TorrentUploadPanel from './TorrentUploadPanel'
import BatchUploadPanel from './BatchUploadPanel'
import ProviderDestinationSelectors from './ProviderDestinationSelectors'
import AdvancedOptions from './AdvancedOptions'
import CreationResultPanel from './CreationResultPanel'

export default function NewJob() {
  const state = useNewJobState()

  return (
    <>
      <PageHeader
        title="New Job"
        description="Submit a magnet link, torrent file, or direct link."
      />

      <div className="flex max-w-3xl flex-col gap-6">
        <SectionCard title="Submit" bodyClassName="p-0">
          <NewJobTabs activeTab={state.activeTab} onTabChange={state.setActiveTab} />

          <div className="p-5">
            {state.activeTab === 'magnet' && (
              <MagnetLinksForm value={state.magnetLinks} onChange={state.setMagnetLinks} />
            )}
            {state.activeTab === 'torrent' && (
              <TorrentUploadPanel
                fileName={state.torrentFileName}
                onFile={state.handleTorrentFile}
              />
            )}
            {state.activeTab === 'batch' && (
              <BatchUploadPanel value={state.batchText} onChange={state.setBatchText} />
            )}
          </div>

          <div className="border-t border-border p-5">
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
          </div>

          <div className="border-t border-border p-5">
            <AdvancedOptions
              open={state.advancedOpen}
              onToggle={() => state.setAdvancedOpen((p) => !p)}
            />
          </div>

          <div className="flex justify-end border-t border-border px-5 py-4">
            <Button onClick={state.handleSubmit} disabled={!state.canSubmit}>
              Create Job
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
