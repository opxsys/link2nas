import { useState } from 'react'
import type { AdminSection, CleanupStatus } from './admin.types'

export function useAdminMockState() {
  const [activeSection, setActiveSection] = useState<AdminSection>('overview')
  const [cleanupStatus, setCleanupStatus] = useState<CleanupStatus>('idle')

  function runCleanup() {
    setCleanupStatus('running')
    setTimeout(() => setCleanupStatus('done'), 2000)
  }

  return {
    activeSection,
    setActiveSection,
    cleanupStatus,
    runCleanup,
  }
}
