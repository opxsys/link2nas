import { useState } from 'react'
import type { SettingsSection } from './settings.types'

export function useSettingsMockState() {
  const [activeSection, setActiveSection] = useState<SettingsSection>('account')
  return { activeSection, setActiveSection }
}
