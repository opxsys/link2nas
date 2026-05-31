import { useState } from 'react'
import type { ProwlarrOpenMode, TestStatus } from './prowlarr.types'
import { MOCK_PROWLARR_CONFIG } from './prowlarr.mock'

export function useProwlarrMockState() {
  const [openMode, setOpenMode] = useState<ProwlarrOpenMode>(MOCK_PROWLARR_CONFIG.openMode)
  const [setAsHomePage, setSetAsHomePage] = useState(MOCK_PROWLARR_CONFIG.setAsHomePage)
  const [testStatus, setTestStatus] = useState<TestStatus>('idle')

  function runMockTest() {
    setTestStatus('testing')
    setTimeout(() => setTestStatus('ok'), 1500)
  }

  return {
    openMode,
    setOpenMode,
    setAsHomePage,
    setSetAsHomePage,
    testStatus,
    runMockTest,
    config: MOCK_PROWLARR_CONFIG,
  }
}
