import { useState } from 'react'
import { cn } from '@/lib/utils'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'

const LANGUAGES = [
  { code: 'en', label: 'English', shortCode: 'EN', note: 'Default' },
  { code: 'fr', label: 'Français', shortCode: 'FR', note: '' },
]

export default function LanguageSettings() {
  const [selected, setSelected] = useState('en')
  const [saved, setSaved] = useState(false)

  function handleSave() {
    setSaved(true)
    setTimeout(() => setSaved(false), 3000)
  }

  return (
    <div className="flex flex-col gap-6">
      <SectionCard title="Language">
        <div className="flex flex-col gap-3">
          {LANGUAGES.map(({ code, label, shortCode, note }) => (
            <button
              key={code}
              onClick={() => setSelected(code)}
              aria-pressed={selected === code}
              className={cn(
                'flex items-center gap-4 rounded-lg border-2 px-4 py-3 text-left text-sm transition-colors',
                selected === code
                  ? 'border-primary bg-primary/5'
                  : 'border-border hover:border-primary/40 hover:bg-muted/30',
              )}
            >
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-muted text-xs font-bold text-foreground">
                {shortCode}
              </div>
              <div className="flex-1">
                <span className="font-medium text-foreground">{label}</span>
                {note && (
                  <span className="ml-2 text-xs text-muted-foreground">{note}</span>
                )}
              </div>
              {selected === code && (
                <span className="text-xs font-medium text-primary">Selected</span>
              )}
            </button>
          ))}
          <p className="text-xs text-muted-foreground">
            Language switching is visual only — not yet applied to the UI.
          </p>
        </div>
      </SectionCard>

      <div className="flex items-center gap-3">
        <Button size="sm" onClick={handleSave}>Save preference</Button>
        {saved && (
          <span className="text-xs text-muted-foreground">Mock changes only — not persisted.</span>
        )}
      </div>
    </div>
  )
}
