import { useState } from 'react'
import { FolderOutput, Pencil, Trash2, FlaskConical, Loader2, CheckCircle2, XCircle, Lock } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { testDestinationConfig } from '@/api/destination-configs'
import { ApiError } from '@/api/client'
import type { DestinationConfig } from '@/api/destination-configs'
import { useI18n } from '@/i18n'
import { DESTINATION_LABEL as TYPE_LABEL } from '@/lib/destination-types'

type TestStatus = 'idle' | 'testing' | 'ok' | 'error'

interface Props {
  config: DestinationConfig
  onEdit: () => void
  onDelete: () => void
  onReload: () => void
}

export default function DestinationRow({ config, onEdit, onDelete }: Props) {
  const { t } = useI18n()
  const [testStatus, setTestStatus] = useState<TestStatus>('idle')
  const [testMessage, setTestMessage] = useState('')

  const typeLabel = TYPE_LABEL[config.destination_type] ?? config.destination_type
  const cfg = config.config

  async function handleTest() {
    setTestStatus('testing')
    setTestMessage('')
    try {
      await testDestinationConfig(config.id)
      setTestStatus('ok')
      setTestMessage(t('destTestOk'))
    } catch (err) {
      setTestStatus('error')
      setTestMessage(err instanceof ApiError ? err.message : t('testFailed'))
    }
  }

  return (
    <div className="flex items-start gap-4 rounded-lg border border-border p-4">
      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-muted text-foreground">
        <FolderOutput size={18} aria-hidden="true" />
      </div>

      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-sm font-medium text-foreground">{config.name}</span>
          <span className="rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground">{typeLabel}</span>
          {config.is_enabled && (
            <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:bg-emerald-900/20 dark:text-emerald-400">{t('badgeActive')}</span>
          )}
          {config.is_default && (
            <span className="rounded-full bg-primary/10 px-2 py-0.5 text-xs font-medium text-primary">{t('badgeDefault')}</span>
          )}
          {config.destination_type === 'synology' && cfg.has_password && (
            <span className="inline-flex items-center gap-1 rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground">
              <Lock size={10} aria-hidden="true" /> {t('badgePasswordSet')}
            </span>
          )}
        </div>

        {config.destination_type === 'synology' && cfg.username && (
          <p className="mt-0.5 text-xs text-muted-foreground">{t('labelUser')}: {cfg.username}</p>
        )}

        {testStatus === 'testing' && (
          <div className="mt-1 flex items-center gap-1.5 text-xs text-muted-foreground">
            <Loader2 size={11} className="animate-spin" aria-hidden="true" />
            <span>{t('testing')}</span>
          </div>
        )}

        {testStatus === 'ok' && (
          <div className="mt-2 flex items-center gap-1.5 rounded-md border border-emerald-200 bg-emerald-50 px-2.5 py-1.5 text-xs text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-400">
            <CheckCircle2 size={11} aria-hidden="true" />
            <span>{testMessage}</span>
          </div>
        )}

        {testStatus === 'error' && (
          <div className="mt-2 flex items-center gap-1.5 rounded-md border border-red-200 bg-red-50 px-2.5 py-1.5 text-xs text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
            <XCircle size={11} aria-hidden="true" />
            <span>{testMessage}</span>
          </div>
        )}
      </div>

      <div className="flex shrink-0 items-center gap-1">
        <Button variant="ghost" size="icon" className="h-7 w-7"
          aria-label={`${t('titleEdit')} ${config.name}`} title={t('titleEdit')} onClick={onEdit}>
          <Pencil size={13} aria-hidden="true" />
        </Button>
        <Button variant="ghost" size="icon" className="h-7 w-7"
          disabled={!config.is_enabled || testStatus === 'testing'}
          aria-label={`${t('testConnection')} ${config.name}`}
          title={!config.is_enabled ? t('destEnableFirst') : t('testConnection')}
          onClick={handleTest}>
          {testStatus === 'testing'
            ? <Loader2 size={13} className="animate-spin" aria-hidden="true" />
            : <FlaskConical size={13} aria-hidden="true" />}
        </Button>
        <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive"
          aria-label={`${t('delete')} ${config.name}`} onClick={onDelete}>
          <Trash2 size={13} aria-hidden="true" />
        </Button>
      </div>
    </div>
  )
}
