import SectionCard from '@/components/common/SectionCard'
import type { DispatcherSettings, OrchestratorSettings, LocalWorkerSettings } from './admin.types'
import { useI18n } from '@/i18n'
import type { TranslationKey } from '@/i18n'

const LABEL = 'text-sm text-foreground'
const HINT = 'ml-1.5 text-xs text-muted-foreground'
const NUM = 'h-9 w-28 rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const CHECK = 'h-4 w-4 rounded border-input accent-primary disabled:opacity-50'
const ROW = 'flex items-center justify-between gap-4'
const CHECK_ROW = 'flex items-center gap-2.5'

interface Props {
  dispatcher: Pick<DispatcherSettings, 'enabled' | 'interval_seconds' | 'limit'>
  dispatcherRuntime: { last_run_at?: string | null; last_error?: string | null }
  orchestrator: OrchestratorSettings
  localWorker: LocalWorkerSettings
  disabled?: boolean
  onDispatcher: (key: 'enabled' | 'interval_seconds' | 'limit', value: boolean | number) => void
  onOrchestrator: (key: keyof OrchestratorSettings, value: boolean | number) => void
  onLocalWorker: (key: keyof LocalWorkerSettings, value: boolean | number) => void
}

export default function AdminRuntimeFields({
  dispatcher, dispatcherRuntime, orchestrator, localWorker, disabled,
  onDispatcher, onOrchestrator, onLocalWorker,
}: Props) {
  const { t } = useI18n()

  const ORCH_CHECKS: { key: keyof OrchestratorSettings; labelKey: TranslationKey }[] = [
    { key: 'auto_refresh_enabled',          labelKey: 'adminRtAutoRefresh'   },
    { key: 'auto_unrestrict_enabled',       labelKey: 'adminRtAutoUnrestrict' },
    { key: 'auto_send_destination_enabled', labelKey: 'adminRtAutoSendDest'  },
  ]

  return (
    <div className="grid gap-4 xl:grid-cols-2">
      {/* Row 1 col 1 — Dispatcher */}
      <SectionCard title={t('adminDispTitle')} description={t('adminDispDesc')}>
        <div className="flex flex-col gap-4">
          <div className={CHECK_ROW}>
            <input id="rt-disp-enabled" type="checkbox" className={CHECK} checked={dispatcher.enabled}
              disabled={disabled} onChange={(e) => onDispatcher('enabled', e.target.checked)} />
            <label htmlFor="rt-disp-enabled" className={LABEL}>{t('labelEnabled')}</label>
          </div>
          <div className={ROW}>
            <label htmlFor="rt-disp-interval" className={LABEL}>
              {t('adminRtIntervalLabel')}<span className={HINT}>(5–86400 s)</span>
            </label>
            <div className="flex shrink-0 items-center gap-2">
              <input id="rt-disp-interval" type="number" className={NUM} value={dispatcher.interval_seconds}
                disabled={disabled} min={5} max={86400}
                onChange={(e) => onDispatcher('interval_seconds', Number(e.target.value))} />
              <span className="text-xs text-muted-foreground">sec</span>
            </div>
          </div>
          <div className={ROW}>
            <label htmlFor="rt-disp-limit" className={LABEL}>
              {t('adminRtBatchLimit')}<span className={HINT}>(1–200)</span>
            </label>
            <input id="rt-disp-limit" type="number" className={NUM} value={dispatcher.limit}
              disabled={disabled} min={1} max={200}
              onChange={(e) => onDispatcher('limit', Number(e.target.value))} />
          </div>
          {(dispatcherRuntime.last_run_at || dispatcherRuntime.last_error) && (
            <div className="rounded-md border border-border bg-muted/30 px-3 py-2.5 text-xs text-muted-foreground">
              {dispatcherRuntime.last_run_at && (
                <p>{t('adminRtLastRun')} {new Date(dispatcherRuntime.last_run_at).toLocaleString()}</p>
              )}
              {dispatcherRuntime.last_error && (
                <p className="mt-0.5 text-amber-700 dark:text-amber-400">
                  {t('adminRtLastError')} {dispatcherRuntime.last_error}
                </p>
              )}
            </div>
          )}
        </div>
      </SectionCard>

      {/* Row 1 col 2 — Local Worker */}
      <SectionCard title={t('adminLwTitle')} description={t('adminLwDesc')}>
        <div className="flex flex-col gap-4">
          <div className={CHECK_ROW}>
            <input id="rt-lw-enabled" type="checkbox" className={CHECK} checked={localWorker.enabled}
              disabled={disabled} onChange={(e) => onLocalWorker('enabled', e.target.checked)} />
            <label htmlFor="rt-lw-enabled" className={LABEL}>{t('labelEnabled')}</label>
          </div>
          <div className={ROW}>
            <label htmlFor="rt-lw-poll" className={LABEL}>
              {t('adminRtPollInterval')}<span className={HINT}>(1–3600 s)</span>
            </label>
            <div className="flex shrink-0 items-center gap-2">
              <input id="rt-lw-poll" type="number" className={NUM} value={localWorker.poll_interval_seconds}
                disabled={disabled} min={1} max={3600}
                onChange={(e) => onLocalWorker('poll_interval_seconds', Number(e.target.value))} />
              <span className="text-xs text-muted-foreground">sec</span>
            </div>
          </div>
          <div className={ROW}>
            <label htmlFor="rt-lw-max" className={LABEL}>
              {t('adminRtMaxConcurrent')}<span className={HINT}>(1–20)</span>
            </label>
            <input id="rt-lw-max" type="number" className={NUM} value={localWorker.max_concurrent_downloads}
              disabled={disabled} min={1} max={20}
              onChange={(e) => onLocalWorker('max_concurrent_downloads', Number(e.target.value))} />
          </div>
        </div>
      </SectionCard>

      {/* Row 2 — Orchestrator full width */}
      <SectionCard className="xl:col-span-2" title={t('adminOrchTitle')} description={t('adminOrchDesc')}>
        <div className="flex flex-col gap-4">
          <div className={CHECK_ROW}>
            <input id="rt-orch-enabled" type="checkbox" className={CHECK} checked={orchestrator.enabled}
              disabled={disabled} onChange={(e) => onOrchestrator('enabled', e.target.checked)} />
            <label htmlFor="rt-orch-enabled" className={LABEL}>{t('labelEnabled')}</label>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className={ROW}>
              <label htmlFor="rt-orch-interval" className={LABEL}>
                {t('adminRtIntervalLabel')}<span className={HINT}>(1–3600 s)</span>
              </label>
              <div className="flex shrink-0 items-center gap-2">
                <input id="rt-orch-interval" type="number" className={NUM} value={orchestrator.interval_seconds}
                  disabled={disabled} min={1} max={3600}
                  onChange={(e) => onOrchestrator('interval_seconds', Number(e.target.value))} />
                <span className="text-xs text-muted-foreground">sec</span>
              </div>
            </div>
            <div className={ROW}>
              <label htmlFor="rt-orch-max" className={LABEL}>
                {t('adminRtMaxJobsRun')}<span className={HINT}>(1–500)</span>
              </label>
              <input id="rt-orch-max" type="number" className={NUM} value={orchestrator.max_jobs_per_run}
                disabled={disabled} min={1} max={500}
                onChange={(e) => onOrchestrator('max_jobs_per_run', Number(e.target.value))} />
            </div>
          </div>
          <div className="flex flex-wrap gap-x-8 gap-y-2.5">
            {ORCH_CHECKS.map(({ key, labelKey }) => (
              <div key={key} className={CHECK_ROW}>
                <input id={`rt-orch-${key}`} type="checkbox" className={CHECK}
                  checked={orchestrator[key] as boolean}
                  disabled={disabled}
                  onChange={(e) => onOrchestrator(key, e.target.checked)} />
                <label htmlFor={`rt-orch-${key}`} className={LABEL}>{t(labelKey)}</label>
              </div>
            ))}
          </div>
        </div>
      </SectionCard>
    </div>
  )
}
