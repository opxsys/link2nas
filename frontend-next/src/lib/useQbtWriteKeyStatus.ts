import { useState, useEffect } from 'react'
import { listMyApiKeys } from '@/api/user-api-keys'

export type QbtWriteKeyStatus = 'loading' | 'ok' | 'missing' | 'error'

const REFETCH_EVENT = 'api-keys-changed'

export function invalidateQbtWriteKeyStatus(): void {
  window.dispatchEvent(new CustomEvent(REFETCH_EVENT))
}

export function useQbtWriteKeyStatus(): QbtWriteKeyStatus {
  const [status, setStatus] = useState<QbtWriteKeyStatus>('loading')

  useEffect(() => {
    let cancelled = false

    function doFetch() {
      setStatus('loading')
      listMyApiKeys()
        .then(keys => {
          if (cancelled) return
          const has = keys.some(k => k.is_active && k.scopes.includes('qbittorrent:write'))
          setStatus(has ? 'ok' : 'missing')
        })
        .catch(() => {
          if (!cancelled) setStatus('error')
        })
    }

    doFetch()
    window.addEventListener(REFETCH_EVENT, doFetch)
    return () => {
      cancelled = true
      window.removeEventListener(REFETCH_EVENT, doFetch)
    }
  }, [])

  return status
}
