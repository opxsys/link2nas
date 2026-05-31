import { useState } from 'react'
import type { AdminSection, TestStatus, CleanupStatus } from './admin.types'

export function useAdminMockState() {
  const [activeSection, setActiveSection] = useState<AdminSection>('overview')
  const [smtpTestStatus, setSmtpTestStatus] = useState<TestStatus>('idle')
  const [cleanupStatus, setCleanupStatus] = useState<CleanupStatus>('idle')

  function runSmtpTest() {
    setSmtpTestStatus('sending')
    setTimeout(() => setSmtpTestStatus('sent'), 1500)
  }

  function runCleanup() {
    setCleanupStatus('running')
    setTimeout(() => setCleanupStatus('done'), 2000)
  }

  return {
    activeSection,
    setActiveSection,
    smtpTestStatus,
    runSmtpTest,
    cleanupStatus,
    runCleanup,
  }
}
