import type { SavedSearch, SearchFilters, SortState } from './prowlarr.types'

const STORAGE_KEY = 'link2nas_prowlarr_saved_searches'

export function loadSavedSearches(): SavedSearch[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

export function upsertSavedSearch(
  name: string,
  filters: SearchFilters,
  sort: SortState,
  existingId?: string,
): SavedSearch[] {
  const all = loadSavedSearches()
  const id = existingId ?? crypto.randomUUID()
  const entry: SavedSearch = {
    id,
    name,
    filters,
    sort,
    saved_at: new Date().toISOString(),
  }
  const idx = all.findIndex((s) => s.id === id)
  const updated = idx >= 0 ? all.map((s) => (s.id === id ? entry : s)) : [...all, entry]
  localStorage.setItem(STORAGE_KEY, JSON.stringify(updated))
  return updated
}

export function deleteSavedSearch(id: string): SavedSearch[] {
  const updated = loadSavedSearches().filter((s) => s.id !== id)
  localStorage.setItem(STORAGE_KEY, JSON.stringify(updated))
  return updated
}
