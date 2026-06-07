import { Pencil, Trash2, FlaskConical, Loader2, CheckCircle2, XCircle, KeyRound } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useI18n } from '@/i18n'
import type { AdminOidcProvider } from './admin.types'

interface DiscoveryResult {
  ok: boolean
  error?: string
}

interface Props {
  provider: AdminOidcProvider
  testResult: DiscoveryResult | null
  testPending: boolean
  onEdit: () => void
  onDelete: () => void
  onTest: () => void
}

export default function AdminSsoProviderRow({
  provider,
  testResult,
  testPending,
  onEdit,
  onDelete,
  onTest,
}: Props) {
  const { t } = useI18n()

  return (
    <div className="flex flex-col gap-2 rounded-md border border-border bg-background px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium text-foreground truncate">{provider.name}</span>
          <span className="rounded bg-muted px-1.5 py-0.5 text-xs text-muted-foreground font-mono">
            {provider.slug}
          </span>
          {provider.enabled ? (
            <span className="rounded-full bg-green-100 px-2 py-0.5 text-xs font-medium text-green-800 dark:bg-green-900/30 dark:text-green-400">
              {t('adminSsoEnabled')}
            </span>
          ) : (
            <span className="rounded-full bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground">
              {t('adminSsoDisabled')}
            </span>
          )}
          {provider.has_client_secret ? (
            <span className="flex items-center gap-1 text-xs text-muted-foreground">
              <KeyRound size={11} aria-hidden="true" />
              {t('adminSsoHasSecret')}
            </span>
          ) : (
            <span className="text-xs text-destructive">{t('adminSsoNoSecret')}</span>
          )}
        </div>
        <p className="mt-0.5 text-xs text-muted-foreground truncate">{provider.issuer}</p>

        {testResult !== null && (
          <div className={`mt-1.5 flex items-center gap-1.5 text-xs ${testResult.ok ? 'text-green-700 dark:text-green-400' : 'text-destructive'}`}>
            {testResult.ok
              ? <CheckCircle2 size={12} aria-hidden="true" />
              : <XCircle size={12} aria-hidden="true" />}
            <span>{testResult.ok ? t('adminSsoDiscoveryOk') : (testResult.error ?? t('adminSsoDiscoveryFailed'))}</span>
          </div>
        )}
      </div>

      <div className="flex shrink-0 items-center gap-1">
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={onTest}
          disabled={testPending}
          title={t('adminSsoTestDiscovery')}
          aria-label={t('adminSsoTestDiscovery')}
          className="h-8 px-2"
        >
          {testPending
            ? <Loader2 size={13} className="animate-spin" aria-hidden="true" />
            : <FlaskConical size={13} aria-hidden="true" />}
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={onEdit}
          title={t('adminSsoEditProvider')}
          aria-label={t('adminSsoEditProvider')}
          className="h-8 px-2"
        >
          <Pencil size={13} aria-hidden="true" />
        </Button>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={onDelete}
          title={t('adminSsoDeleteProvider')}
          aria-label={t('adminSsoDeleteProvider')}
          className="h-8 px-2 text-destructive hover:bg-destructive/10 hover:text-destructive"
        >
          <Trash2 size={13} aria-hidden="true" />
        </Button>
      </div>
    </div>
  )
}
