import type {
  MockDestinationProfile,
  MockProwlarrConfig,
} from './settings.types'

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

export const MOCK_PROWLARR: MockProwlarrConfig = {
  enabled: true,
  url: 'http://nas.local:9696',
  openMode: 'iframe',
  setAsHomePage: false,
}
