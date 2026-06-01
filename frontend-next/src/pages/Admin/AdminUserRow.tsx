import { Ban, UserCheck, Link2, Mail, KeyRound, BadgeCheck, Trash2, Loader2, Pencil } from 'lucide-react'
import { Button } from '@/components/ui/button'
import type { RealUser } from './admin.types'

const BADGE = 'inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium'
const ROLE_CLASS: Record<string, string> = {
  super_admin: 'border-purple-200 bg-purple-50 text-purple-700 dark:border-purple-800 dark:bg-purple-950 dark:text-purple-400',
  user:        'border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-800 dark:bg-blue-950 dark:text-blue-400',
}
const ICON_BTN = 'h-7 w-7'

function fmtDate(iso: string | null | undefined): string {
  return iso ? new Date(iso).toLocaleDateString() : '—'
}

function isExpired(iso: string | null | undefined): boolean {
  return Boolean(iso && new Date(iso) < new Date())
}

export interface UserRowHandlers {
  onEdit: () => void
  onEnable: () => void
  onDisable: () => void
  onDelete: () => void
  onVerifyEmail: () => void
  onGetInvitationLink: () => void
  onSendInvitationEmail: () => void
  onGetResetLink: () => void
  onSendResetEmail: () => void
}

interface Props {
  user: RealUser
  isActing: boolean
  smtpAvailable: boolean
  handlers: UserRowHandlers
}

export default function AdminUserRow({ user, isActing, smtpAvailable, handlers }: Props) {
  const dis = isActing
  const expired = isExpired(user.account_expires_at)

  return (
    <tr className="border-b border-border last:border-0 hover:bg-muted/30">
      <td className="px-4 py-2.5">
        <p className="text-sm font-medium text-foreground">{user.display_name || user.email}</p>
        {user.display_name && <p className="text-xs text-muted-foreground">{user.email}</p>}
        {user.preferred_language && user.preferred_language !== 'en' && (
          <p className="text-xs text-muted-foreground uppercase">{user.preferred_language}</p>
        )}
      </td>
      <td className="px-4 py-2.5">
        <span className={`${BADGE} ${ROLE_CLASS[user.role] ?? ROLE_CLASS.user}`}>
          {user.is_super_admin ? 'Super admin' : 'User'}
        </span>
      </td>
      <td className="px-4 py-2.5">
        <div className="flex flex-wrap gap-1">
          <span className={`${BADGE} ${user.is_active
            ? 'border-green-200 bg-green-50 text-green-700 dark:border-green-800 dark:bg-green-950 dark:text-green-400'
            : 'border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400'}`}>
            {user.is_active ? 'Active' : 'Disabled'}
          </span>
          {expired && (
            <span className={`${BADGE} border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-800 dark:bg-orange-950 dark:text-orange-400`}>
              Expired
            </span>
          )}
        </div>
      </td>
      <td className="px-4 py-2.5 text-center text-xs">
        {user.email_verified
          ? <span className="text-emerald-600 dark:text-emerald-400">✓</span>
          : <span className="text-muted-foreground">—</span>}
      </td>
      <td className="px-4 py-2.5 text-xs text-muted-foreground">{fmtDate(user.created_at)}</td>
      <td className="px-4 py-2.5 text-xs text-muted-foreground">
        {user.last_login_at ? fmtDate(user.last_login_at) : <span className="italic">Never</span>}
      </td>
      <td className="px-4 py-2.5">
        <div className="flex flex-wrap items-center gap-0.5">
          {isActing ? (
            <Loader2 size={14} className="animate-spin text-muted-foreground" aria-hidden="true" />
          ) : (
            <>
              <Button variant="ghost" size="icon" className={ICON_BTN} disabled={dis} aria-label={`Edit ${user.email}`} onClick={handlers.onEdit}>
                <Pencil size={13} />
              </Button>
              {user.is_active ? (
                <Button variant="ghost" size="icon" className={ICON_BTN} disabled={dis} aria-label={`Disable ${user.email}`} onClick={handlers.onDisable}>
                  <Ban size={13} />
                </Button>
              ) : (
                <Button variant="ghost" size="icon" className={ICON_BTN} disabled={dis} aria-label={`Enable ${user.email}`} onClick={handlers.onEnable}>
                  <UserCheck size={13} />
                </Button>
              )}
              {!user.email_verified && (
                <Button variant="ghost" size="icon" className={ICON_BTN} disabled={dis} aria-label="Mark email verified" onClick={handlers.onVerifyEmail}>
                  <BadgeCheck size={13} />
                </Button>
              )}
              <Button variant="ghost" size="icon" className={ICON_BTN} disabled={dis} aria-label="Copy invitation link" onClick={handlers.onGetInvitationLink}>
                <Link2 size={13} />
              </Button>
              <Button variant="ghost" size="icon" className={`${ICON_BTN} ${!smtpAvailable ? 'opacity-40' : ''}`}
                disabled={dis || !smtpAvailable} aria-label={smtpAvailable ? 'Send invitation email' : 'SMTP not configured'} onClick={handlers.onSendInvitationEmail}>
                <Mail size={13} />
              </Button>
              <Button variant="ghost" size="icon" className={ICON_BTN} disabled={dis} aria-label="Copy password reset link" onClick={handlers.onGetResetLink}>
                <KeyRound size={13} />
              </Button>
              <Button variant="ghost" size="icon" className={`${ICON_BTN} ${!smtpAvailable ? 'opacity-40' : ''}`}
                disabled={dis || !smtpAvailable} aria-label={smtpAvailable ? 'Send password reset email' : 'SMTP not configured'} onClick={handlers.onSendResetEmail}>
                <Mail size={13} className="text-amber-600 dark:text-amber-400" />
              </Button>
              <Button variant="ghost" size="icon" className={`${ICON_BTN} text-destructive hover:text-destructive`} disabled={dis} aria-label={`Delete ${user.email}`} onClick={handlers.onDelete}>
                <Trash2 size={13} />
              </Button>
            </>
          )}
        </div>
      </td>
    </tr>
  )
}
