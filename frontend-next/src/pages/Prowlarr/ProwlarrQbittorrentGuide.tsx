import { Info } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { useI18n } from '@/i18n'
import { useAppInfo } from '@/lib/useAppInfo'

export default function ProwlarrQbittorrentGuide() {
  const { t } = useI18n()
  const { appInfo } = useAppInfo()
  const appName = appInfo.app_name || 'Link2NAS'

  const steps = [
    t('prowlarrStep1'),
    t('prowlarrStep2'),
    `${t('prowlarrStep3Pre')} ${appName} ${t('prowlarrStep3Post')}`,
    t('prowlarrStep4'),
    t('prowlarrStep5'),
    t('prowlarrStep6'),
    `${t('prowlarrStep7Pre')} ${appName} ${t('prowlarrStep7Post')}`,
    t('prowlarrStep8'),
    t('prowlarrStep9'),
    t('prowlarrStep10'),
  ]

  return (
    <SectionCard
      title={t('prowlarrSetupGuide')}
      description={`${t('prowlarrSetupDescPre')} ${appName}.`}
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
        <span>
          {appName} {t('prowlarrNotePart1')} <code className="font-mono">qbittorrent:write</code> {t('prowlarrNotePart2')}
        </span>
      </div>
    </SectionCard>
  )
}
