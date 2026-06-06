export interface DestinationTypeDef {
  value: string
  label: string
}

export const DESTINATION_TYPES: DestinationTypeDef[] = [
  { value: 'synology', label: 'Synology NAS' },
  { value: 'local',    label: 'Local'         },
]

export const DESTINATION_LABEL: Record<string, string> = Object.fromEntries(
  DESTINATION_TYPES.map((d) => [d.value, d.label]),
)
