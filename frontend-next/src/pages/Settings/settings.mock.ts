import type {
  MockAccount,
  MockProviderProfile,
  MockDestinationProfile,
  MockNotificationRule,
  MockProwlarrConfig,
} from './settings.types'

export const MOCK_ACCOUNT: MockAccount = {
  username: 'admin',
  email: 'admin@maison.local',
  role: 'Administrator',
}

export const MOCK_PROVIDERS: MockProviderProfile[] = [
  {
    id: 'rd-perso',
    name: 'Real-Debrid (perso)',
    type: 'realdebrid',
    typeLabel: 'Real-Debrid',
    isActive: true,
    isDefault: true,
  },
  {
    id: 'alldebrid',
    name: 'AllDebrid',
    type: 'alldebrid',
    typeLabel: 'AllDebrid',
    isActive: true,
    isDefault: false,
  },
]

export const MOCK_DESTINATIONS: MockDestinationProfile[] = [
  {
    id: 'nas-maison',
    name: 'NAS Maison',
    type: 'nfs',
    typeLabel: 'NFS',
    path: '/mnt/nas/downloads',
    isActive: true,
    isDefault: true,
  },
  {
    id: 'nas-backup',
    name: 'NAS Backup',
    type: 'nfs',
    typeLabel: 'NFS',
    path: '/mnt/backup/downloads',
    isActive: false,
    isDefault: false,
  },
]

export const MOCK_NOTIFICATION_RULES: MockNotificationRule[] = [
  { id: 'r1', event: 'Job completed', channel: 'Email', enabled: true },
  { id: 'r2', event: 'Job failed', channel: 'Email', enabled: true },
  { id: 'r3', event: 'Job cancelled', channel: 'Email', enabled: false },
]

export const MOCK_PROWLARR: MockProwlarrConfig = {
  enabled: true,
  url: 'http://nas.local:9696',
  openMode: 'iframe',
  setAsHomePage: false,
}
