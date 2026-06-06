import { useI18n } from '@/i18n'

interface MagnetLinksFormProps {
  value: string
  onChange: (value: string) => void
}

export default function MagnetLinksForm({ value, onChange }: MagnetLinksFormProps) {
  const { t } = useI18n()
  const lineCount = value.trim() ? value.trim().split('\n').filter(Boolean).length : 0

  return (
    <div className="flex flex-col gap-3">
      <div>
        <label
          htmlFor="magnet-links-input"
          className="mb-1.5 block text-xs font-medium text-foreground"
        >
          {t('magnetLinksLabel')}
        </label>
        <textarea
          id="magnet-links-input"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={
            'magnet:?xt=urn:btih:…\nhttps://example.com/file.torrent\n\nOne link per line'
          }
          rows={7}
          spellCheck={false}
          className="w-full resize-y rounded-md border border-input bg-background px-3 py-2 font-mono text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring"
          aria-describedby="magnet-links-hint"
        />
      </div>
      <p id="magnet-links-hint" className="text-xs text-muted-foreground">
        {lineCount > 0
          ? `${lineCount} ${lineCount !== 1 ? t('links') : t('link')} ${t('entered')}`
          : t('magnetLinksHint')}
      </p>
    </div>
  )
}
