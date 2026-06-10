import { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import PageHeader from '@/components/layout/PageHeader'
import { useSettingsMockState } from './useSettingsMockState'
import type { SettingsSection } from './settings.types'
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
import { useAppInfo } from '@/lib/useAppInfo'
import { useI18n } from '@/i18n'

const VALID_SECTIONS: SettingsSection[] = [
  'account', 'providers', 'destinations', 'api-keys',
  'notifications', 'prowlarr', 'accessibility', 'space',
]

function resolveSection(param: string | null): SettingsSection {
  return VALID_SECTIONS.includes(param as SettingsSection)
    ? (param as SettingsSection)
    : 'account'
}

export default function Settings() {
  const [searchParams] = useSearchParams()
  const { activeSection, setActiveSection } = useSettingsMockState(
    resolveSection(searchParams.get('section')),
  )
  const [canUseSpace, setCanUseSpace] = useState(false)
  const { appInfo } = useAppInfo()
  const appName = appInfo.app_name || 'Link2NAS'
  const { t } = useI18n()

  useEffect(() => {
    getMe().then(me => setCanUseSpace(me.can_use_local_space)).catch(() => {})
  }, [])

  return (
    <>
      <PageHeader title={t('navSettings')} description={`${t('settingsDescPre')} ${appName} ${t('settingsDescPost')}`} />
      <div className="flex flex-col gap-6 lg:flex-row lg:items-start">
        <SettingsNav activeSection={activeSection} onSelect={setActiveSection} showSpace={canUseSpace} />
        <div className="min-w-0 flex-1">
          {activeSection === 'account' && <AccountSettings />}
          {activeSection === 'providers' && <ProviderSettings />}
          {activeSection === 'destinations' && <DestinationSettings />}
          {activeSection === 'api-keys' && <ApiKeysSettings />}
          {activeSection === 'notifications' && <NotificationSettings />}
          {activeSection === 'prowlarr' && <ProwlarrSettings />}
          {activeSection === 'accessibility' && <AccessibilitySettings />}
          {activeSection === 'space' && canUseSpace && <UserSpaceSettings />}
        </div>
      </div>
    </>
  )
}
