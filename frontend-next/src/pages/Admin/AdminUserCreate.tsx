import { useState } from 'react'
import { Loader2, XCircle } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { createUser } from '@/api/admin-users'
import { useSmtpStatus } from '@/lib/useSmtpStatus'
import type { CreateUserResponse } from './admin.types'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const SELECT = INPUT
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'
const CHECK = 'h-4 w-4 rounded border-input accent-primary disabled:opacity-50'
const HINT = 'text-xs text-muted-foreground'

interface Props {
  onSave: (result: CreateUserResponse) => void
  onCancel: () => void
}

export default function AdminUserCreate({ onSave, onCancel }: Props) {
  const { smtpAvailable } = useSmtpStatus()
  const [mode, setMode] = useState<'password' | 'invitation'>('invitation')
  const [email, setEmail] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [language, setLanguage] = useState('')
  const [password, setPassword] = useState('')
  const [forcePasswordChange, setForcePasswordChange] = useState(true)
  const [validFrom, setValidFrom] = useState('')
  const [expiresAt, setExpiresAt] = useState('')
  const [isSuperAdmin, setIsSuperAdmin] = useState(false)
  const [emailVerified, setEmailVerified] = useState(false)
  const [canUseLocalSpace, setCanUseLocalSpace] = useState(false)
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
        force_password_change: mode === 'password' ? forcePasswordChange : undefined,
        display_name: displayName.trim() || undefined,
        preferred_language: language || undefined,
        valid_from: validFrom || null,
        account_expires_at: expiresAt || null,
        is_super_admin: isSuperAdmin,
        email_verified: emailVerified,
        can_use_local_space: canUseLocalSpace,
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
            <label key={m} className="flex cursor-pointer items-center gap-2 text-sm text-foreground">
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
            <label htmlFor="cu-name" className={LABEL}>Display name <span className={HINT}>(optional)</span></label>
            <input id="cu-name" type="text" className={INPUT} value={displayName} disabled={saving}
              onChange={(e) => setDisplayName(e.target.value)} />
          </div>
        </div>

        <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
          <div>
            <label htmlFor="cu-lang" className={LABEL}>Language</label>
            <select id="cu-lang" className={SELECT} value={language} disabled={saving}
              onChange={(e) => setLanguage(e.target.value)}>
              <option value="">Default (en)</option>
              <option value="en">English</option>
              <option value="fr">Français</option>
            </select>
          </div>
        </div>

        {mode === 'password' && (
          <div className="flex flex-col gap-4">
            <div>
              <label htmlFor="cu-pw" className={LABEL}>Password <span className="text-destructive">*</span></label>
              <input id="cu-pw" type="password" className={INPUT} value={password} disabled={saving}
                required autoComplete="new-password" onChange={(e) => setPassword(e.target.value)} />
            </div>
            <label className="flex cursor-pointer items-center gap-2 text-sm text-foreground">
              <input type="checkbox" className={CHECK} checked={forcePasswordChange} disabled={saving}
                onChange={(e) => setForcePasswordChange(e.target.checked)} />
              Force password change at next login
            </label>
          </div>
        )}

        <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
          <div>
            <label htmlFor="cu-vf" className={LABEL}>Valid from <span className={HINT}>(optional)</span></label>
            <input id="cu-vf" type="datetime-local" className={INPUT} value={validFrom} disabled={saving}
              onChange={(e) => setValidFrom(e.target.value)} />
          </div>
          <div>
            <label htmlFor="cu-ea" className={LABEL}>Account expires <span className={HINT}>(optional)</span></label>
            <input id="cu-ea" type="datetime-local" className={INPUT} value={expiresAt} disabled={saving}
              onChange={(e) => setExpiresAt(e.target.value)} />
          </div>
        </div>

        <div className="flex flex-wrap gap-5">
          {([
            [isSuperAdmin, setIsSuperAdmin, 'cu-super', 'Super admin'],
            [emailVerified, setEmailVerified, 'cu-verified', 'Mark email verified'],
            [canUseLocalSpace, setCanUseLocalSpace, 'cu-space', 'Can use local space'],
          ] as [boolean, (v: boolean) => void, string, string][]).map(([val, setter, id, label]) => (
            <label key={id} className="flex cursor-pointer items-center gap-2 text-sm text-foreground">
              <input id={id} type="checkbox" className={CHECK} checked={val} disabled={saving}
                onChange={(e) => setter(e.target.checked)} />
              {label}
            </label>
          ))}
        </div>

        {mode === 'invitation' && !smtpAvailable && (
          <p className="text-xs text-amber-700 dark:text-amber-400">
            SMTP is not configured or disabled. Email sending is unavailable. The invitation link will be shown after creation.
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
