import { useState } from 'react'
import { Loader2, Info } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { changePassword } from '@/api/me'
import { ApiError } from '@/api/client'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'

interface Props {
  singleUserMode: boolean
}

export default function AccountPasswordCard({ singleUserMode }: Props) {
  const [currentPw, setCurrentPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [confirmPw, setConfirmPw] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)

  async function handleSave() {
    setError(null)
    if (!currentPw) { setError('Current password is required.'); return }
    if (!newPw)     { setError('New password is required.'); return }
    if (newPw !== confirmPw) { setError('Passwords do not match.'); return }

    setSaving(true)
    setSaved(false)
    try {
      await changePassword({ current_password: currentPw, new_password: newPw })
      setCurrentPw('')
      setNewPw('')
      setConfirmPw('')
      setSaved(true)
      setTimeout(() => setSaved(false), 4000)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to change password')
    } finally {
      setSaving(false)
    }
  }

  return (
    <SectionCard title="Change Password">
      {singleUserMode ? (
        <div className="flex items-start gap-2 rounded-md bg-muted/50 p-3 text-sm text-muted-foreground">
          <Info size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
          Password change is disabled in single-user mode.
        </div>
      ) : (
        <>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="sm:col-span-2 sm:max-w-xs">
              <label htmlFor="acc-current-pw" className={LABEL}>Current password</label>
              <input id="acc-current-pw" type="password" value={currentPw}
                onChange={(e) => setCurrentPw(e.target.value)}
                placeholder="••••••••" className={INPUT} autoComplete="current-password" />
            </div>
            <div>
              <label htmlFor="acc-new-pw" className={LABEL}>New password</label>
              <input id="acc-new-pw" type="password" value={newPw}
                onChange={(e) => setNewPw(e.target.value)}
                placeholder="••••••••" className={INPUT} autoComplete="new-password" />
            </div>
            <div>
              <label htmlFor="acc-confirm-pw" className={LABEL}>Confirm new password</label>
              <input id="acc-confirm-pw" type="password" value={confirmPw}
                onChange={(e) => setConfirmPw(e.target.value)}
                placeholder="••••••••" className={INPUT} autoComplete="new-password" />
            </div>
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-border pt-4">
            <Button size="sm" onClick={handleSave} disabled={saving}>
              {saving && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
              Change password
            </Button>
            {saved && <span className="text-xs text-green-600 dark:text-green-400">Password changed.</span>}
            {error && <span className="text-xs text-destructive">{error}</span>}
          </div>
        </>
      )}
    </SectionCard>
  )
}
