import PageHeader from '@/components/layout/PageHeader'
import { useProwlarrMockState } from './useProwlarrMockState'
import ProwlarrStatusCard from './ProwlarrStatusCard'
import ProwlarrEmbedPreview from './ProwlarrEmbedPreview'
import ProwlarrConnectionSettings from './ProwlarrConnectionSettings'
import ProwlarrQbittorrentGuide from './ProwlarrQbittorrentGuide'
import ProwlarrRecentSubmissions from './ProwlarrRecentSubmissions'

export default function Prowlarr() {
  const {
    openMode,
    setOpenMode,
    setAsHomePage,
    setSetAsHomePage,
    testStatus,
    runMockTest,
    config,
  } = useProwlarrMockState()

  return (
    <>
      <PageHeader
        title="Prowlarr"
        description="Manage your Prowlarr integration and qBittorrent compatibility API."
      />
      <div className="flex flex-col gap-6">
        <div className="grid gap-6 lg:grid-cols-2">
          <ProwlarrStatusCard
            url={config.url}
            connectionStatus={config.connectionStatus}
            openMode={openMode}
            setAsHomePage={setAsHomePage}
            onOpenModeChange={setOpenMode}
            onHomePageToggle={setSetAsHomePage}
          />
          <ProwlarrEmbedPreview url={config.url} openMode={openMode} />
        </div>
        <ProwlarrConnectionSettings testStatus={testStatus} onTest={runMockTest} />
        <ProwlarrQbittorrentGuide />
        <ProwlarrRecentSubmissions />
      </div>
    </>
  )
}
