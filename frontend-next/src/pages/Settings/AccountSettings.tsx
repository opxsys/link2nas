import { useState } from 'react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { MOCK_ACCOUNT } from './settings.mock'

const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring'
const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'

export default function AccountSettings() {
  const [username, setUsername] = useState(MOCK_ACCOUNT.username)
  const [email, setEmail] = useState(MOCK_ACCOUNT.email)
  const [currentPw, setCurrentPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [saved, setSaved] = useState(false)

  function handleSave() {
    setSaved(true)
    setTimeout(() => setSaved(false), 3000)
  }

  return (
    <div className="flex flex-col gap-6">
      <SectionCard title="Profile">
        <div className="mb-5 flex items-center gap-4 border-b border-border pb-5">
          <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-primary/10 text-lg font-bold uppercase text-primary">
            {MOCK_ACCOUNT.username.charAt(0)}
          </div>
          <div>
            <p className="text-sm font-medium text-foreground">{MOCK_ACCOUNT.username}</p>
            <p className="text-xs text-muted-foreground">{MOCK_ACCOUNT.role}</p>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div>
            <label htmlFor="acc-username" className={LABEL}>Username</label>
            <input
              id="acc-username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className={INPUT}
            />
          </div>
          <div>
            <label htmlFor="acc-email" className={LABEL}>Email</label>
            <input
              id="acc-email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className={INPUT}
            />
          </div>
          <p className="text-xs text-muted-foreground sm:col-span-2">
            Role:{' '}
            <span className="font-medium text-foreground">{MOCK_ACCOUNT.role}</span>
            {' '}— managed by administrator.
          </p>
        </div>
      </SectionCard>

      <SectionCard title="Change Password">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div>
            <label htmlFor="acc-current-pw" className={LABEL}>Current password</label>
            <input
              id="acc-current-pw"
              type="password"
              value={currentPw}
              onChange={(e) => setCurrentPw(e.target.value)}
              placeholder="••••••••"
              className={INPUT}
            />
          </div>
          <div>
            <label htmlFor="acc-new-pw" className={LABEL}>New password</label>
            <input
              id="acc-new-pw"
              type="password"
              value={newPw}
              onChange={(e) => setNewPw(e.target.value)}
              placeholder="••••••••"
              className={INPUT}
            />
          </div>
        </div>
      </SectionCard>

      <div className="flex items-center gap-3">
        <Button size="sm" onClick={handleSave}>Save changes</Button>
        {saved && (
          <span className="text-xs text-muted-foreground">Mock changes only — not persisted.</span>
        )}
      </div>
    </div>
  )
}
