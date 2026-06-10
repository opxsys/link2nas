export interface ProwlarrCategory {
  id: number
  label: string
  group: string
}

export const PROWLARR_CATEGORIES: ProwlarrCategory[] = [
  { id: 2000, label: 'Movies',          group: 'Movies' },
  { id: 2030, label: 'Movies/SD',       group: 'Movies' },
  { id: 2040, label: 'Movies/HD',       group: 'Movies' },
  { id: 2045, label: 'Movies/UHD',      group: 'Movies' },
  { id: 2050, label: 'Movies/BluRay',   group: 'Movies' },
  { id: 2060, label: 'Movies/3D',       group: 'Movies' },
  { id: 5000, label: 'TV',              group: 'TV' },
  { id: 5030, label: 'TV/SD',           group: 'TV' },
  { id: 5040, label: 'TV/HD',           group: 'TV' },
  { id: 5045, label: 'TV/UHD',          group: 'TV' },
  { id: 5060, label: 'TV/Sport',        group: 'TV' },
  { id: 5070, label: 'TV/Anime',        group: 'TV' },
  { id: 5080, label: 'TV/Documentary',  group: 'TV' },
  { id: 3000, label: 'Audio',           group: 'Audio' },
  { id: 3010, label: 'Audio/MP3',       group: 'Audio' },
  { id: 3040, label: 'Audio/Lossless',  group: 'Audio' },
  { id: 4000, label: 'PC',              group: 'PC' },
  { id: 4010, label: 'PC/0day',         group: 'PC' },
  { id: 4050, label: 'PC/Mobile',       group: 'PC' },
  { id: 8000, label: 'Books',           group: 'Books' },
  { id: 8010, label: 'Books/Magazines', group: 'Books' },
  { id: 8020, label: 'Books/eBook',     group: 'Books' },
]

export function groupedCategories(): Record<string, ProwlarrCategory[]> {
  return PROWLARR_CATEGORIES.reduce<Record<string, ProwlarrCategory[]>>((acc, cat) => {
    if (!acc[cat.group]) acc[cat.group] = []
    acc[cat.group].push(cat)
    return acc
  }, {})
}
