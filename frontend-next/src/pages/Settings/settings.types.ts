export type SettingsSection =
  | 'account'
  | 'providers'
  | 'destinations'
  | 'api-keys'
  | 'notifications'
  | 'prowlarr'
  | 'accessibility'
  | 'space'

export interface MockProwlarrConfig {
  enabled: boolean
  url: string
  openMode: 'iframe' | 'newtab'
  setAsHomePage: boolean
}
