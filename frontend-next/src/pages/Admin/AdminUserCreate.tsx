import { useState } from 'react'
import { Loader2, XCircle } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { createUser } from '@/api/admin-users'
import { useSmtpStatus } from '@/lib/useSmtpStatus'
import type { CreateUserResponse } from './admin.types'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'
const CHECK = 'h-4 w-4 rounded border-input accent-primary disabled:opacity-50'

interface Props {
  onSave: (result: CreateUserResponse) => void
  onCancel: () => void
}

export default function AdminUserCreate({ onSave, onCancel }: Props) {
  const { smtpAvailable } = useSmtpStatus()
  const [mode, setMode] = useState<'password' | 'invitation'>('invitation')
  const [email, setEmail] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')
  const [isSuperAdmin, setIsSuperAdmin] = useState(false)
  const [emailVerified, setEmailVerified] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setSaving(true)
    setError('')
    try {
      const result = await createUser({
        email: email.trim().toLowerCase(),
        creation_mode: mode,
        password: mode === 'password' ? password : undefined,
        display_name: displayName.trim() || undefined,
        is_super_admin: isSuperAdmin,
        email_verified: emailVerified,
      })
      onSave(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create user.')
      setSaving(false)
    }
  }

  return (
    <SectionCard title="Create User">
      <form onSubmit={handleSubmit} className="flex flex-col gap-5">
        <div className="flex gap-4">
          {(['invitation', 'password'] as const).map((m) => (
            <label key={m} className="flex items-center gap-2 text-sm text-foreground cursor-pointer">
              <input type="radio" name="mode" value={m} checked={mode === m}
                onChange={() => setMode(m)} className={CHECK} />
              {m === 'invitation' ? 'Invitation link' : 'Set password now'}
            </label>
          ))}
        </div>

        <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
          <div>
            <label htmlFor="cu-email" className={LABEL}>Email <span className="text-destructive">*</span></label>
            <input id="cu-email" type="email" className={INPUT} value={email} disabled={saving}
              required onChange={(e) => setEmail(e.target.value)} />
          </div>
          <div>
            <label htmlFor="cu-name" className={LABEL}>Display name <span className="text-muted-foreground">(optional)</span></label>
            <input id="cu-name" type="text" className={INPUT} value={displayName} disabled={saving}
              onChange={(e) => setDisplayName(e.target.value)} />
          </div>
        </div>

        {mode === 'password' && (
          <div>
            <label htmlFor="cu-pw" className={LABEL}>Password <span className="text-destructive">*</span></label>
            <input id="cu-pw" type="password" className={INPUT} value={password} disabled={saving}
              required autoComplete="new-password" onChange={(e) => setPassword(e.target.value)} />
          </div>
        )}

        <div className="flex flex-wrap gap-6">
          <label className="flex items-center gap-2 text-sm text-foreground cursor-pointer">
            <input type="checkbox" className={CHECK} checked={isSuperAdmin} disabled={saving}
              onChange={(e) => setIsSuperAdmin(e.target.checked)} />
            Super admin
          </label>
          <label className="flex items-center gap-2 text-sm text-foreground cursor-pointer">
            <input type="checkbox" className={CHECK} checked={emailVerified} disabled={saving}
              onChange={(e) => setEmailVerified(e.target.checked)} />
            Mark email verified
          </label>
        </div>

        {mode === 'invitation' && !smtpAvailable && (
          <p className="text-xs text-amber-700 dark:text-amber-400">
            SMTP is not configured or disabled. The invitation link will be shown after creation — copy it manually.
          </p>
        )}

        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" size="sm" disabled={saving}>
            {saving && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
            Create
          </Button>
          <Button type="button" size="sm" variant="outline" disabled={saving} onClick={onCancel}>
            Cancel
          </Button>
          {error && (
            <span className="flex items-center gap-1.5 text-sm text-red-700 dark:text-red-400">
              <XCircle size={14} aria-hidden="true" /> {error}
            </span>
          )}
        </div>
      </form>
    </SectionCard>
  )
}
