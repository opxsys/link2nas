const STORAGE_KEY = 'link2nas-sidebar-collapsed'

export function getStoredSidebarState(): boolean {
  try {
    return localStorage.getItem(STORAGE_KEY) === 'true'
  } catch {
    return false
  }
}

export function storeSidebarState(collapsed: boolean): void {
  try {
    localStorage.setItem(STORAGE_KEY, String(collapsed))
  } catch {
    // localStorage unavailable
  }
}
