import { useState } from 'react'
import { Copy, CheckCircle2 } from 'lucide-react'
import UnavailableState from '@/components/common/UnavailableState'
import { useI18n } from '@/i18n'
import { formatBytes } from './jobs.types'
import type { RealJobFile } from '@/api/jobs'

interface JobFilesTableProps {
  files: RealJobFile[]
  onUnrestrictFile?: (fileId: string | number) => void
  fileBusy?: boolean
}

const TH = 'px-4 py-2 text-left text-xs font-medium text-muted-foreground'
const TD = 'px-4 py-2.5'

function CopyLinkButton({ url, label }: { url: string; label: string }) {
  const { t } = useI18n()
  const [copied, setCopied] = useState(false)

  function handleCopy() {
    navigator.clipboard.writeText(url).catch(() => undefined)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <button
      onClick={handleCopy}
      className="rounded text-muted-foreground hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      aria-label={`${t('copy')} ${label}`}
      title={t('copy')}
    >
      {copied ? <CheckCircle2 size={13} className="text-green-600" /> : <Copy size={13} />}
    </button>
  )
}

export default function JobFilesTable({
  files,
  onUnrestrictFile,
  fileBusy,
}: JobFilesTableProps) {
  const { t } = useI18n()

  if (files.length === 0) {
    return (
      <UnavailableState
        message={t('noFilesAvailable')}
        note={t('noFilesNote')}
        className="py-6"
      />
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b border-border bg-muted/20">
            <th className={TH}>{t('colFile')}</th>
            <th className={TH}>{t('colSize')}</th>
            <th className={`${TH} text-right`}>
              <span className="sr-only">{t('colActions')}</span>
            </th>
          </tr>
        </thead>

        <tbody className="divide-y divide-border">
          {files.map((file, index) => {
            const name = file.filename || file.path || `file_${index + 1}`
            const link = file.download_url || file.debrid_link
            const canUnlock = !!onUnrestrictFile && (!!file.debrid_link || !!file.download_url)

            return (
              <tr key={String(file.id)} className="hover:bg-muted/30">
                <td className={TD}>
                  <span
                    className="block max-w-[220px] truncate text-xs font-medium text-foreground"
                    title={name}
                  >
                    {name}
                  </span>
                </td>

                <td className={`${TD} text-xs text-muted-foreground`}>
                  {formatBytes(file.filesize ?? file.bytes)}
                </td>

                <td className={`${TD} text-right`}>
                  <div className="flex items-center justify-end gap-2">
                    {canUnlock && (
                      <button
                        onClick={() => onUnrestrictFile(file.id)}
                        disabled={fileBusy}
                        className="text-xs text-muted-foreground hover:text-primary disabled:cursor-not-allowed disabled:opacity-50"
                        title={file.download_url ? 'Generate a fresh direct download link from the provider.' : 'Generate a direct download link from the provider.'}
                      >
                        {file.download_url ? t('regenerate') : t('generateLink')}
                      </button>
                    )}

                    {link && <CopyLinkButton url={link} label={name} />}
                  </div>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
