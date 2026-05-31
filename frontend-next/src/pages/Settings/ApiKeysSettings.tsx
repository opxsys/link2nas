import { Plus, Trash2 } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { MOCK_API_KEYS } from './settings.mock'

const TH = 'px-4 py-2.5 text-left text-xs font-medium text-muted-foreground'
const TD = 'px-4 py-3'

export default function ApiKeysSettings() {
  return (
    <SectionCard
      title="API Keys"
      description="Keys used for external integrations such as qBittorrent and Prowlarr."
      actions={
        <Button variant="outline" size="sm" disabled>
          <Plus size={13} aria-hidden="true" /> Create key
        </Button>
      }
      bodyClassName="p-0"
    >
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/30">
              <th className={TH}>Name</th>
              <th className={TH}>Key</th>
              <th className={TH}>Scopes</th>
              <th className={TH}>Created</th>
              <th className={`${TH} hidden sm:table-cell`}>Last used</th>
              <th className={TH}><span className="sr-only">Actions</span></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {MOCK_API_KEYS.map((key) => (
              <tr key={key.id}>
                <td className={`${TD} font-medium text-foreground`}>{key.name}</td>
                <td className={TD}>
                  <code className="rounded bg-muted px-2 py-0.5 text-xs text-muted-foreground">
                    {key.maskedKey}
                  </code>
                </td>
                <td className={TD}>
                  <div className="flex flex-wrap gap-1">
                    {key.scopes.map((scope) => (
                      <span
                        key={scope}
                        className="rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground"
                      >
                        {scope}
                      </span>
                    ))}
                  </div>
                </td>
                <td className={`${TD} text-muted-foreground`}>{key.createdAt}</td>
                <td className={`${TD} hidden text-muted-foreground sm:table-cell`}>
                  {key.lastUsedAt ?? '—'}
                </td>
                <td className={`${TD} text-right`}>
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled
                    className="text-destructive/50 hover:text-destructive"
                    aria-label={`Revoke ${key.name}`}
                  >
                    <Trash2 size={13} aria-hidden="true" /> Revoke
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="border-t border-border px-4 py-3 text-xs text-muted-foreground">
        Key creation and revocation are not yet available in this UI.
      </p>
    </SectionCard>
  )
}
