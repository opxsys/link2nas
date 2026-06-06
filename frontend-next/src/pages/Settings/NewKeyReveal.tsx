import { useState } from 'react'
import { Copy, CheckCircle2, AlertTriangle, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useI18n } from '@/i18n'

interface Props {
  keyName: string
  rawKey: string
  onDismiss: () => void
}

export default function NewKeyReveal({ keyName, rawKey, onDismiss }: Props) {
  const { t } = useI18n()
  const [copied, setCopied] = useState(false)
  const [copyFailed, setCopyFailed] = useState(false)

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(rawKey)
      setCopied(true)
      setCopyFailed(false)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      setCopyFailed(true)
      setTimeout(() => setCopyFailed(false), 4000)
    }
  }

  return (
    <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 dark:border-amber-800 dark:bg-amber-950">
      <div className="mb-3 flex items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          <AlertTriangle size={15} className="shrink-0 text-amber-600 dark:text-amber-400" aria-hidden="true" />
          <p className="text-sm font-semibold text-amber-800 dark:text-amber-200">
            {t('newKeyTitle')}
          </p>
        </div>
        <button
          type="button"
          onClick={onDismiss}
          aria-label={t('dismiss')}
          className="rounded p-0.5 text-amber-600 hover:bg-amber-100 dark:text-amber-400 dark:hover:bg-amber-900"
        >
          <X size={14} aria-hidden="true" />
        </button>
      </div>

      <p className="mb-3 text-xs text-amber-700 dark:text-amber-400">
        {t('newKeyNotePre')} <strong>{keyName}</strong> {t('newKeyNotePost')}
      </p>

      <div className="flex items-center gap-2">
        <code className="flex-1 overflow-x-auto rounded border border-amber-200 bg-white px-3 py-2 text-xs font-mono text-foreground dark:border-amber-700 dark:bg-black/30 dark:text-amber-100">
          {rawKey}
        </code>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={handleCopy}
          className="shrink-0 border-amber-300 bg-white text-amber-700 hover:bg-amber-100 dark:border-amber-700 dark:bg-transparent dark:text-amber-300"
        >
          {copied
            ? <><CheckCircle2 size={13} className="mr-1.5" aria-hidden="true" />{t('copied')}</>
            : <><Copy size={13} className="mr-1.5" aria-hidden="true" />{t('copy')}</>
          }
        </Button>
      </div>

      {copyFailed && (
        <p className="mt-2 text-xs text-amber-700 dark:text-amber-400">
          {t('copyFailed')}
        </p>
      )}
    </div>
  )
}
