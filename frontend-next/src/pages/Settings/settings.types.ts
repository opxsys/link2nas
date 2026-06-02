export type SettingsSection =
  | 'account'
  | 'providers'
  | 'destinations'
  | 'api-keys'
  | 'notifications'
  | 'prowlarr'
  | 'accessibility'
  | 'language'

export interface MockProwlarrConfig {
  enabled: boolean
  url: string
  openMode: 'iframe' | 'newtab'
  setAsHomePage: boolean
}
