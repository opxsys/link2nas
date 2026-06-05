export const en = {
  // Navigation labels
  navDashboard:     'Dashboard',
  navJobs:          'Jobs',
  navAnnouncements: 'Announcements',
  navProwlarr:      'Prowlarr',
  navNotifications: 'My Notifications',
  navSettings:      'Settings',
  navAdmin:         'Admin',
  navMaintenance:   'System Status',
  navNewJob:        'New Job',
  navProviders:     'Providers',
  navDestinations:  'Destinations',
  // Account menu
  myAccount:   'My Account',
  appearance:  'Appearance',
  language:    'Language',
  signOut:     'Sign out',
  langSystem:  'System',
  langEnglish: 'English',
  langFrench:  'Français',
  // Role labels
  roleSuperAdmin:   'Super Admin',
  roleUser:         'User',
  roleAdministrator:'Administrator',
  // Theme labels
  themeAuto:         'Auto',
  themeLight:        'Light',
  themeDark:         'Dark',
  themeHighContrast: 'High Contrast',
  themeColorblind:   'Colorblind',
  // Accessible labels
  ariaGoHome:          'Go to home page',
  ariaAccountSettings: 'Go to account settings',
  ariaExpandSidebar:   'Expand sidebar',
  ariaCollapseSidebar: 'Collapse sidebar',
  ariaOpenNav:         'Open navigation',
  ariaMobileNav:       'Navigation',
  ariaCloseNav:        'Close navigation',
  ariaSelectTheme:     'Select theme',
} as const

export type TranslationKey = keyof typeof en
export type Translations   = Record<TranslationKey, string>
