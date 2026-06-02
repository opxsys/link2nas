export type SettingsSection =
  | 'account'
  | 'providers'
  | 'destinations'
  | 'api-keys'
  | 'notifications'
  | 'prowlarr'
  | 'accessibility'
  | 'language'

export interface MockAccount {
  username: string
  email: string
  role: string
}

export interface MockProviderProfile {
  id: string
  name: string
  type: string
  typeLabel: string
  isActive: boolean
  isDefault: boolean
}

export interface MockDestinationProfile {
  id: string
  name: string
  type: string
  typeLabel: string
  path: string
  isActive: boolean
  isDefault: boolean
}

export interface MockProwlarrConfig {
  enabled: boolean
  url: string
  openMode: 'iframe' | 'newtab'
  setAsHomePage: boolean
}
