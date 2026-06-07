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
  identity_proxy_enabled: boolean
  identity_proxy_label: string
  identity_proxy_auto_login: boolean
  identity_proxy_provider_type: string
}

export function getAppInfo(): Promise<AppInfo> {
  return request<AppInfo>('/api/v2/public/app-info')
}
