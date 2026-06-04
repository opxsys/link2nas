import { useState } from 'react'
import type { SettingsSection } from './settings.types'

export function useSettingsMockState(initialSection: SettingsSection = 'account') {
  const [activeSection, setActiveSection] = useState<SettingsSection>(initialSection)
  return { activeSection, setActiveSection }
}
