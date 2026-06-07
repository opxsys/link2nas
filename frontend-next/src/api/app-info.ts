import { request } from './client'

export interface OidcPublicProvider {
  slug: string
  button_label: string
}

export interface AppInfo {
  app_name: string
  app_tagline: string
  email_sending_available: boolean
  oidc_enabled: boolean
  oidc_label: string
  oidc_providers: OidcPublicProvider[]
}

export function getAppInfo(): Promise<AppInfo> {
  return request<AppInfo>('/api/v2/public/app-info')
}
