import { Cloud, Zap } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

export interface ProviderTypeDef {
  value: string
  label: string
  icon: LucideIcon
}

export const PROVIDER_TYPES: ProviderTypeDef[] = [
  { value: 'realdebrid', label: 'Real-Debrid', icon: Zap   },
  { value: 'alldebrid',  label: 'AllDebrid',   icon: Cloud },
]

export const PROVIDER_LABEL: Record<string, string> = Object.fromEntries(
  PROVIDER_TYPES.map((p) => [p.value, p.label]),
)

export const PROVIDER_ICON: Record<string, LucideIcon> = Object.fromEntries(
  PROVIDER_TYPES.map((p) => [p.value, p.icon]),
)
