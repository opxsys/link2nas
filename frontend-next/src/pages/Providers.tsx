import PageHeader from '@/components/layout/PageHeader'
import { useI18n } from '@/i18n'

export default function Providers() {
  const { t } = useI18n()
  return (
    <>
      <PageHeader
        title={t('navProviders')}
        description={t('providersPageDesc')}
      />
      <div className="rounded-lg border border-border bg-card p-8 text-center text-sm text-muted-foreground">
        {t('providersComingSoon')}
      </div>
    </>
  )
}
