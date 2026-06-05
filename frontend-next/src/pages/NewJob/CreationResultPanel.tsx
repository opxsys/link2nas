import { useNavigate } from 'react-router-dom'
import { CircleCheck, CircleX, Link as LinkIcon, ChevronRight } from 'lucide-react'
import { cn } from '@/lib/utils'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import type { NewJobResult } from './newJob.types'

interface CreationResultPanelProps {
  result: NewJobResult
  onDismiss: () => void
}

const TH = 'px-4 py-2 text-left text-xs font-medium text-muted-foreground'
const TD = 'px-4 py-3'

export default function CreationResultPanel({ result, onDismiss }: CreationResultPanelProps) {
  const navigate = useNavigate()
  const allOk = result.failed === 0
  const allFailed = result.created === 0

  const singleJobId = result.created === 1
    ? (result.items.find(i => i.status !== 'failed')?.jobId ?? null)
    : null

  return (
    <SectionCard
      title="Submission result"
      actions={
        <Button variant="ghost" size="sm" onClick={onDismiss}>
          Dismiss
        </Button>
      }
    >
      <div className="flex flex-col gap-4">
        {/* Summary banner */}
        <div
          className={cn(
            'flex flex-wrap items-center gap-3 rounded-md px-4 py-3 text-sm',
            allOk && 'bg-emerald-50 text-emerald-800 dark:bg-emerald-900/20 dark:text-emerald-300',
            allFailed && 'bg-red-50 text-red-800 dark:bg-red-900/20 dark:text-red-300',
            !allOk && !allFailed && 'bg-amber-50 text-amber-800 dark:bg-amber-900/20 dark:text-amber-300',
          )}
        >
          {allOk
            ? <CircleCheck size={16} aria-hidden="true" />
            : <CircleX size={16} aria-hidden="true" />}
          <span>
            {result.submitted} submitted —{' '}
            <strong>{result.created} created</strong>
            {result.failed > 0 && (
              <>, <strong>{result.failed} failed</strong></>
            )}
          </span>
          {result.created > 0 && (
            <button
              type="button"
              onClick={() => navigate('/jobs', singleJobId ? { state: { selectedJobId: singleJobId } } : undefined)}
              className="ml-auto flex items-center gap-1 text-xs underline-offset-2 hover:underline"
            >
              {singleJobId ? 'View job' : 'View jobs'} <ChevronRight size={12} aria-hidden="true" />
            </button>
          )}
        </div>

        {/* Per-item table */}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className={TH}>Input</th>
                <th className={TH}>Status</th>
                <th className={TH}>Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {result.items.map((item) => (
                <tr key={item.id}>
                  <td className={TD}>
                    <span
                      className="flex items-center gap-1.5 font-mono text-xs text-muted-foreground"
                      title={item.input}
                    >
                      <LinkIcon size={11} className="shrink-0" aria-hidden="true" />
                      <span className="max-w-[260px] truncate">{item.input}</span>
                    </span>
                  </td>
                  <td className={TD}>
                    {item.status === 'created' ? (
                      <span className="flex items-center gap-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-400">
                        <CircleCheck size={13} aria-hidden="true" /> Created
                      </span>
                    ) : (
                      <span className="flex items-center gap-1.5 text-xs font-medium text-red-700 dark:text-red-400">
                        <CircleX size={13} aria-hidden="true" /> Failed
                      </span>
                    )}
                  </td>
                  <td className={TD}>
                    <span className="font-mono text-xs text-muted-foreground">
                      {item.jobId ?? item.error ?? '—'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </SectionCard>
  )
}
