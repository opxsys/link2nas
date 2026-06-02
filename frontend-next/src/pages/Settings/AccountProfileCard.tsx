import { useState, useEffect } from 'react'
import { CheckCircle2, AlertCircle, Loader2 } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { updateMe, requestEmailVerification } from '@/api/me'
import { ApiError } from '@/api/client'
import type { MeProfile } from '@/api/me'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'

const LANGUAGES = [
  { value: '', label: 'System default' },
  { value: 'en', label: 'English' },
  { value: 'fr', label: 'Français' },
]

interface Props {
  me: MeProfile
  onUpdate: (updated: MeProfile) => void
}

export default function AccountProfileCard({ me, onUpdate }: Props) {
  const [displayName, setDisplayName] = useState(me.display_name ?? '')
  const [email, setEmail] = useState(me.email)
  const [lang, setLang] = useState(me.preferred_language ?? '')
  const [receiveEmails, setReceiveEmails] = useState(me.receive_application_emails)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState(false)
  const [verifySending, setVerifySending] = useState(false)
  const [verifyMsg, setVerifyMsg] = useState<{ ok: boolean; text: string } | null>(null)

  useEffect(() => {
    setDisplayName(me.display_name ?? '')
    setEmail(me.email)
    setLang(me.preferred_language ?? '')
    setReceiveEmails(me.receive_application_emails)
    setVerifyMsg(null)
  }, [me])

  async function handleSave() {
    setSaving(true)
    setError(null)
    setSaved(false)
    try {
      const updated = await updateMe({
        display_name: displayName.trim() || null,
        email: email.trim(),
        preferred_language: lang || null,
        receive_application_emails: receiveEmails,
      })
      onUpdate(updated)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to save profile')
    } finally {
      setSaving(false)
    }
  }

  async function handleRequestVerification() {
    setVerifySending(true)
    setVerifyMsg(null)
    try {
      const res = await requestEmailVerification()
      setVerifyMsg({ ok: res.ok, text: res.message ?? 'Verification email sent.' })
    } catch (err) {
      setVerifyMsg({ ok: false, text: err instanceof ApiError ? err.message : 'Failed to send verification email.' })
    } finally {
      setVerifySending(false)
    }
  }

  const initials = (me.display_name || me.email).charAt(0).toUpperCase()
  const emailChanged = email.trim() !== me.email
  const roleLabel = me.role === 'super_admin' ? 'Super Admin' : me.role === 'user' ? 'User' : me.role

  return (
    <SectionCard title="Profile & Preferences">
      {/* Avatar + identity row */}
      <div className="mb-5 flex items-center gap-4 border-b border-border pb-5">
        <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-primary/10 text-lg font-bold uppercase text-primary">
          {initials}
        </div>
        <div className="min-w-0">
          <p className="text-sm font-medium text-foreground">{me.display_name || me.email}</p>
          <div className="mt-1 flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center rounded-full border border-border bg-muted px-2 py-0.5 text-xs text-muted-foreground">
              {roleLabel}
            </span>
            {me.email_verified ? (
              <span className="inline-flex items-center gap-1 rounded-full border border-green-200 bg-green-50 px-2 py-0.5 text-xs text-green-700 dark:border-green-800 dark:bg-green-950 dark:text-green-400">
                <CheckCircle2 size={10} aria-hidden="true" /> Verified
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 rounded-full border border-amber-200 bg-amber-50 px-2 py-0.5 text-xs text-amber-700 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-400">
                <AlertCircle size={10} aria-hidden="true" /> Email not verified
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Editable fields */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <div>
          <label htmlFor="acc-display-name" className={LABEL}>Display name</label>
          <input id="acc-display-name" type="text" value={displayName}
            onChange={(e) => setDisplayName(e.target.value)} className={INPUT} />
        </div>
        <div>
          <label htmlFor="acc-email" className={LABEL}>Email</label>
          <input id="acc-email" type="email" value={email}
            onChange={(e) => setEmail(e.target.value)} className={INPUT} />
          {emailChanged && !me.single_user_mode && (
            <p className="mt-1 text-xs text-amber-600 dark:text-amber-400">
              Changing email will require re-verification.
            </p>
          )}
        </div>

        <div>
          <label htmlFor="acc-lang" className={LABEL}>Preferred language</label>
          <select id="acc-lang" value={lang}
            onChange={(e) => setLang(e.target.value)}
            className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring">
            {LANGUAGES.map((l) => <option key={l.value} value={l.value}>{l.label}</option>)}
          </select>
        </div>

        {me.email_sending_available && (
          <div className="flex items-center gap-3 sm:col-span-1">
            <label className="flex cursor-pointer items-center gap-2 text-sm text-foreground">
              <input type="checkbox" checked={receiveEmails}
                onChange={(e) => setReceiveEmails(e.target.checked)}
                className="h-4 w-4 rounded border-input accent-primary" />
              Receive application emails
            </label>
          </div>
        )}

        <p className="text-xs text-muted-foreground sm:col-span-2">
          Role is managed by an administrator and cannot be changed here.
          {me.last_login_at && (
            <> · Last login: {new Date(me.last_login_at).toLocaleString()}</>
          )}
        </p>
      </div>

      {/* Email verification action */}
      {!me.email_verified && (
        <div className="mt-4 rounded-md border border-amber-200 bg-amber-50 p-3 dark:border-amber-800 dark:bg-amber-950">
          <p className="text-xs text-amber-800 dark:text-amber-300">
            Your email address is not verified. Magic login may be unavailable until verification is complete.
          </p>
          <div className="mt-2 flex flex-wrap items-center gap-3">
            <Button size="sm" variant="outline" onClick={handleRequestVerification} disabled={verifySending}>
              {verifySending && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
              Send verification email
            </Button>
            {verifyMsg && (
              <span className={`text-xs ${verifyMsg.ok ? 'text-green-600 dark:text-green-400' : 'text-destructive'}`}>
                {verifyMsg.text}
              </span>
            )}
          </div>
        </div>
      )}

      {/* Footer */}
      <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-border pt-4">
        <Button size="sm" onClick={handleSave} disabled={saving}>
          {saving && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
          Save profile
        </Button>
        {saved && <span className="text-xs text-green-600 dark:text-green-400">Saved.</span>}
        {error && <span className="text-xs text-destructive">{error}</span>}
      </div>
    </SectionCard>
  )
}
