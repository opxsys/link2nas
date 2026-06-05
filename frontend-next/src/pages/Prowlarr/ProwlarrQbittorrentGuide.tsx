import { Info } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { useAppInfo } from '@/lib/useAppInfo'

export default function ProwlarrQbittorrentGuide() {
  const { appInfo } = useAppInfo()
  const appName = appInfo.app_name || 'Link2NAS'

  const steps = [
    'In Prowlarr, go to Settings → Download Clients.',
    'Click the + button and choose qBittorrent.',
    `Set the Host to your ${appName} address (e.g. link2nas.local or 192.168.1.x).`,
    'Set the Port to 5000 (or your configured port).',
    'Set the URL Base to /api/qbt.',
    'Leave Username blank or set any value — it is not checked.',
    `Set the Password to a ${appName} API key with the qbittorrent:write scope.`,
    'Set Category to prowlarr.',
    'Click Test — Prowlarr should report success.',
    'Save the download client.',
  ]

  return (
    <SectionCard
      title="Setup Guide"
      description={`How to configure Prowlarr to send downloads to ${appName}.`}
    >
      <ol className="flex flex-col gap-2.5">
        {steps.map((step, i) => (
          <li key={i} className="flex items-start gap-3 text-sm text-foreground">
            <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-semibold text-muted-foreground">
              {i + 1}
            </span>
            <span>{step}</span>
          </li>
        ))}
      </ol>
      <div className="mt-4 flex items-start gap-2 rounded-md bg-muted/50 p-3 text-xs text-muted-foreground">
        <Info size={13} className="mt-0.5 shrink-0" aria-hidden="true" />
        {appName} never stores your Prowlarr credentials.
        Each user can configure their own Prowlarr instance independently.
        The API key must have the <code className="font-mono">qbittorrent:write</code> scope.
      </div>
    </SectionCard>
  )
}
