import { RefreshCw, Mail, Trash2, Bell } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'

export default function MaintenanceActions() {
  return (
    <SectionCard title="Actions">
      <div className="flex flex-wrap gap-3">
        <Button variant="outline" size="sm">
          <RefreshCw size={14} aria-hidden="true" />
          Refresh Health
        </Button>
        <Button variant="outline" size="sm" disabled>
          <Mail size={14} aria-hidden="true" />
          Test SMTP
        </Button>
        <Button variant="outline" size="sm" disabled>
          <Trash2 size={14} aria-hidden="true" />
          Run Cleanup
        </Button>
        <Button variant="outline" size="sm" disabled>
          <Bell size={14} aria-hidden="true" />
          Process Notifications
        </Button>
      </div>
      <p className="mt-3 text-xs text-muted-foreground">
        Disabled actions require backend endpoints not yet connected to this UI.
      </p>
    </SectionCard>
  )
}
