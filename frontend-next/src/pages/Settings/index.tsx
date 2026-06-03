import { useState, useEffect } from 'react'
import PageHeader from '@/components/layout/PageHeader'
import { useSettingsMockState } from './useSettingsMockState'
import SettingsNav from './SettingsNav'
import AccountSettings from './AccountSettings'
import ProviderSettings from './ProviderSettings'
import DestinationSettings from './DestinationSettings'
import ApiKeysSettings from './ApiKeysSettings'
import NotificationSettings from './NotificationSettings'
import ProwlarrSettings from './ProwlarrSettings'
import AccessibilitySettings from './AccessibilitySettings'
import UserSpaceSettings from './UserSpaceSettings'
import { getMe } from '@/api/me'

export default function Settings() {
  const { activeSection, setActiveSection } = useSettingsMockState()
  const [canUseSpace, setCanUseSpace] = useState(false)

  useEffect(() => {
    getMe().then(me => setCanUseSpace(me.can_use_local_space)).catch(() => {})
  }, [])

  return (
    <>
      <PageHeader title="Settings" description="Configure your Link2NAS instance." />
      <div className="flex flex-col gap-6 lg:flex-row lg:items-start">
        <SettingsNav activeSection={activeSection} onSelect={setActiveSection} showSpace={canUseSpace} />
        <div className="min-w-0 flex-1">
          {activeSection === 'account' && <AccountSettings />}
          {activeSection === 'providers' && <ProviderSettings />}
          {activeSection === 'destinations' && <DestinationSettings />}
          {activeSection === 'api-keys' && <ApiKeysSettings />}
          {activeSection === 'notifications' && <NotificationSettings />}
          {activeSection === 'prowlarr' && (
            <ProwlarrSettings onGoToApiKeys={() => setActiveSection('api-keys')} />
          )}
          {activeSection === 'accessibility' && <AccessibilitySettings />}
          {activeSection === 'space' && canUseSpace && <UserSpaceSettings />}
        </div>
      </div>
    </>
  )
}
