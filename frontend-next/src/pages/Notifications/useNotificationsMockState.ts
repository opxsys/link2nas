import { useState } from 'react'
import type { ChannelType, TestStatus } from './notifications.types'
import { MOCK_RULES } from './notifications.mock'

export function useNotificationsMockState() {
  const [enabledRules, setEnabledRules] = useState<Set<string>>(
    () => new Set(MOCK_RULES.filter((r) => r.enabled).map((r) => r.id)),
  )
  const [testChannel, setTestChannel] = useState<ChannelType>('email')
  const [testStatus, setTestStatus] = useState<TestStatus>('idle')

  function toggleRule(id: string) {
    setEnabledRules((prev) => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  function runMockTest() {
    setTestStatus('sending')
    setTimeout(() => setTestStatus('sent'), 1500)
  }

  return { enabledRules, toggleRule, testChannel, setTestChannel, testStatus, runMockTest }
}
