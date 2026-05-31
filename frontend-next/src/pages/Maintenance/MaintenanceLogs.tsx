import SectionCard from '@/components/common/SectionCard'
import UnavailableState from '@/components/common/UnavailableState'

export default function MaintenanceLogs() {
  return (
    <SectionCard title="Recent Logs">
      <UnavailableState
        message="Log tail not available"
        note="Connect a log endpoint to enable this section."
      />
    </SectionCard>
  )
}
