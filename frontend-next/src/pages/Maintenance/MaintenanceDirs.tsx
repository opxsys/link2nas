import { CircleCheck, CircleX, AlertCircle } from 'lucide-react'
import { cn } from '@/lib/utils'
import SectionCard from '@/components/common/SectionCard'
import type { MaintenanceStatus } from '@/pages/Admin/admin.types'
import { useI18n } from '@/i18n'

type DirStatus = 'ok' | 'error' | 'unknown'

const STATUS_ICON: Record<DirStatus, typeof CircleCheck> = {
  ok: CircleCheck,
  error: CircleX,
  unknown: AlertCircle,
}

const STATUS_CLASS: Record<DirStatus, string> = {
  ok: 'text-emerald-600 dark:text-emerald-400',
  error: 'text-red-600 dark:text-red-400',
  unknown: 'text-amber-600 dark:text-amber-400',
}

interface Props {
  status: MaintenanceStatus
}

export default function MaintenanceDirs({ status }: Props) {
  const { t } = useI18n()

  const STATUS_LABEL: Record<DirStatus, string> = {
    ok: t('maintStatusOk'),
    error: t('maintStatusError'),
    unknown: t('maintStatusUnknown'),
  }

  if (status.paths.length === 0) {
    return (
      <SectionCard title={t('maintDirsTitle')}>
        <p className="text-sm text-muted-foreground">{t('maintNoDirs')}</p>
      </SectionCard>
    )
  }

  return (
    <SectionCard title={t('maintDirsTitle')} bodyClassName="p-0">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="px-4 pb-2.5 pt-3 text-left text-xs font-medium text-muted-foreground">
                {t('maintColDirectory')}
              </th>
              <th className="px-4 pb-2.5 pt-3 text-left text-xs font-medium text-muted-foreground">
                {t('maintColPath')}
              </th>
              <th className="px-4 pb-2.5 pt-3 text-left text-xs font-medium text-muted-foreground">
                {t('colStatus')}
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {status.paths.map((p) => {
              const dirStatus: DirStatus = p.ok ? 'ok' : p.path === null ? 'unknown' : 'error'
              const Icon = STATUS_ICON[dirStatus]
              return (
                <tr key={p.name} className="hover:bg-muted/40">
                  <td className="px-4 py-2.5 font-medium text-foreground">
                    {p.name}{!p.required && <span className="ml-1 text-xs text-muted-foreground">{t('maintDirOpt')}</span>}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs text-muted-foreground">
                    {p.path ?? '—'}
                  </td>
                  <td className="px-4 py-2.5">
                    <span
                      className={cn(
                        'flex items-center gap-1.5 text-xs font-medium',
                        STATUS_CLASS[dirStatus],
                      )}
                    >
                      <Icon size={14} aria-hidden="true" />
                      {STATUS_LABEL[dirStatus]}
                    </span>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </SectionCard>
  )
}
