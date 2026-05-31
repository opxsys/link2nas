import { Pencil, Ban, KeyRound, Trash2 } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import type { AdminUser, UserRole, UserStatus } from './admin.types'
import { MOCK_USERS } from './admin-users.mock'

const ROLE_STYLE: Record<UserRole, string> = {
  admin:  'border-purple-200 bg-purple-50 text-purple-700 dark:border-purple-800 dark:bg-purple-950 dark:text-purple-400',
  user:   'border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-800 dark:bg-blue-950 dark:text-blue-400',
  viewer: 'border-border bg-muted text-muted-foreground',
}

const STATUS_STYLE: Record<UserStatus, string> = {
  active:   'border-green-200 bg-green-50 text-green-700 dark:border-green-800 dark:bg-green-950 dark:text-green-400',
  disabled: 'border-red-200 bg-red-50 text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400',
  pending:  'border-yellow-200 bg-yellow-50 text-yellow-700 dark:border-yellow-800 dark:bg-yellow-950 dark:text-yellow-400',
}

const BADGE = 'inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium capitalize'

function UserRow({ user }: { user: AdminUser }) {
  return (
    <tr className="border-b border-border last:border-0 hover:bg-muted/30">
      <td className="px-4 py-2.5 font-medium text-sm text-foreground">{user.username}</td>
      <td className="px-4 py-2.5 text-sm text-muted-foreground">{user.email}</td>
      <td className="px-4 py-2.5">
        <span className={`${BADGE} ${ROLE_STYLE[user.role]}`}>{user.role}</span>
      </td>
      <td className="px-4 py-2.5">
        <span className={`${BADGE} ${STATUS_STYLE[user.status]}`}>{user.status}</span>
      </td>
      <td className="px-4 py-2.5 text-center text-xs">
        {user.emailVerified
          ? <span className="text-green-600 dark:text-green-400">✓</span>
          : <span className="text-muted-foreground">—</span>
        }
      </td>
      <td className="px-4 py-2.5 text-xs text-muted-foreground">
        {user.lastLogin ?? <span className="italic">Never</span>}
      </td>
      <td className="px-4 py-2.5">
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="icon" aria-label={`Edit ${user.username}`} className="h-7 w-7"><Pencil size={13} /></Button>
          <Button variant="ghost" size="icon" aria-label={`Disable ${user.username}`} className="h-7 w-7"><Ban size={13} /></Button>
          <Button variant="ghost" size="icon" aria-label={`Reset password for ${user.username}`} className="h-7 w-7"><KeyRound size={13} /></Button>
          <Button variant="ghost" size="icon" aria-label={`Delete ${user.username}`} className="h-7 w-7 text-destructive hover:text-destructive"><Trash2 size={13} /></Button>
        </div>
      </td>
    </tr>
  )
}

export default function AdminUsers() {
  return (
    <SectionCard
      title="Users"
      description="All user accounts on this Link2NAS instance."
      actions={<Button size="sm" variant="outline" disabled>Invite user</Button>}
    >
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Username</th>
              <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Email</th>
              <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Role</th>
              <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Status</th>
              <th className="px-4 py-2 text-xs font-medium text-muted-foreground text-center">Verified</th>
              <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Last login</th>
              <th className="px-4 py-2 text-xs font-medium text-muted-foreground">Actions</th>
            </tr>
          </thead>
          <tbody>
            {MOCK_USERS.map((user) => <UserRow key={user.id} user={user} />)}
          </tbody>
        </table>
      </div>
    </SectionCard>
  )
}
