import { request } from './client'

export interface AppInfo {
  app_name: string
  app_tagline: string
  email_sending_available: boolean
}

export function getAppInfo(): Promise<AppInfo> {
  return request<AppInfo>('/api/v2/public/app-info')
}
