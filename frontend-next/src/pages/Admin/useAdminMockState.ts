import { useState } from 'react'
import type { AdminSection } from './admin.types'

export function useAdminMockState() {
  const [activeSection, setActiveSection] = useState<AdminSection>('overview')
  return { activeSection, setActiveSection }
}
