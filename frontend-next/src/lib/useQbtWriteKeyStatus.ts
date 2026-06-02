import { useState, useEffect } from 'react'
import { listMyApiKeys } from '@/api/user-api-keys'

export type QbtWriteKeyStatus = 'loading' | 'ok' | 'missing' | 'error'

const REFETCH_EVENT = 'api-keys-changed'

export function invalidateQbtWriteKeyStatus(): void {
  window.dispatchEvent(new CustomEvent(REFETCH_EVENT))
}

function hasQbtWriteKey(data: unknown): boolean {
  if (!Array.isArray(data)) return false
  return data.some(k =>
    k !== null &&
    typeof k === 'object' &&
    k.is_active === true &&
    k.revoked_at === null &&
    Array.isArray(k.scopes) &&
    (k.scopes as unknown[]).includes('qbittorrent:write')
  )
}

export function useQbtWriteKeyStatus(): QbtWriteKeyStatus {
  const [status, setStatus] = useState<QbtWriteKeyStatus>('loading')

  useEffect(() => {
    let live = true
    let reqId = 0

    function doFetch() {
      const id = ++reqId
      setStatus('loading')
      listMyApiKeys()
        .then(keys => {
          if (!live || id !== reqId) return
          setStatus(hasQbtWriteKey(keys) ? 'ok' : 'missing')
        })
        .catch(() => {
          if (!live || id !== reqId) return
          setStatus('error')
        })
    }

    doFetch()
    window.addEventListener(REFETCH_EVENT, doFetch)
    return () => {
      live = false
      window.removeEventListener(REFETCH_EVENT, doFetch)
    }
  }, [])

  return status
}
