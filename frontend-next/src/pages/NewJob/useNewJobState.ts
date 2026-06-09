import { useState, useEffect } from 'react'
import { useI18n } from '@/i18n'
import { listProviderConfigs } from '@/api/provider-configs'
import { listDestinationConfigs } from '@/api/destination-configs'
import { createBulkJobs, createTorrentJob } from '@/api/jobs'
import { ApiError } from '@/api/client'
import type { ProviderConfig } from '@/api/provider-configs'
import type { DestinationConfig } from '@/api/destination-configs'
import type { NewJobTab, NewJobResult, NewJobResultItem } from './newJob.types'

export function useNewJobState() {
  const { t } = useI18n()
  const [activeTab, setActiveTab] = useState<NewJobTab>('magnet')
  const [magnetLinks, setMagnetLinks] = useState('')
  // torrent: multiple files
  const [torrentFiles, setTorrentFiles] = useState<File[]>([])

  const [providers, setProviders] = useState<ProviderConfig[]>([])
  const [destinations, setDestinations] = useState<DestinationConfig[]>([])
  const [providerId, setProviderId] = useState('')
  const [destinationId, setDestinationId] = useState('')
  const [linksOnly, setLinksOnly] = useState(false)
  const [advancedOpen, setAdvancedOpen] = useState(false)
  const [configsLoading, setConfigsLoading] = useState(true)
  const [configsError, setConfigsError] = useState<string | null>(null)

  const [submitting, setSubmitting] = useState(false)
  const [result, setResult] = useState<NewJobResult | null>(null)

  useEffect(() => {
    let cancelled = false
    async function loadConfigs() {
      setConfigsLoading(true)
      setConfigsError(null)
      try {
        const [prov, dest] = await Promise.all([listProviderConfigs(), listDestinationConfigs()])
        if (cancelled) return
        const ep = prov.filter(p => p.is_enabled)
        const ed = dest.filter(d => d.is_enabled)
        setProviders(ep)
        setDestinations(ed)
        const defProv = ep.find(p => p.is_default) ?? ep[0]
        const defDest = ed.find(d => d.is_default) // never auto-pick if no default
        if (defProv) setProviderId(defProv.id)
        if (defDest) { setDestinationId(defDest.id); setLinksOnly(false) }
        else { setDestinationId(''); setLinksOnly(true) }
      } catch (err) {
        if (!cancelled) setConfigsError(err instanceof ApiError ? err.message : t('configsLoadFailed'))
      } finally {
        if (!cancelled) setConfigsLoading(false)
      }
    }
    loadConfigs()
    return () => { cancelled = true }
  }, [])

  // torrent_filename kept for compat with TorrentUploadPanel single-file prop
  const torrentFileName = torrentFiles.length === 1 ? torrentFiles[0].name : torrentFiles.length > 1 ? `${torrentFiles.length} files` : null

  const canSubmit = !submitting && !configsLoading && !!providerId && (
    (activeTab === 'magnet'  && magnetLinks.trim().length > 0) ||
    (activeTab === 'torrent' && torrentFiles.length > 0)
  )

  const hasSendDestination = !linksOnly && !!destinationId

  async function handleSubmit() {
    if (!canSubmit || !providerId) return
    setSubmitting(true)
    setResult(null)
    const destId = hasSendDestination ? destinationId : undefined
    const sendToDest = hasSendDestination

    try {
      if (activeTab === 'torrent') {
        // Multi-torrent batch: one API call per file, sequential (mirrors legacy createTorrentFilesBatch)
        const items: NewJobResultItem[] = []
        for (const file of torrentFiles) {
          try {
            const res = await createTorrentJob(file, {
              provider_config_id: providerId,
              destination_config_id: destId,
              auto_start: true,
              send_to_destination: sendToDest,
            })
            const itemErr = res.error ?? (res.job?.error_message ?? null)
            items.push({
              id: res.job?.id ?? `err-${file.name}`,
              input: file.name,
              status: itemErr ? 'failed' : res.reused ? 'reused' : 'created',
              jobId: res.job?.id,
              error: itemErr ?? undefined,
            })
          } catch (err) {
            items.push({
              id: `err-${file.name}`,
              input: file.name,
              status: 'failed',
              error: err instanceof ApiError ? err.message : t('uploadFailed'),
            })
          }
        }
        const created = items.filter(i => i.status !== 'failed').length
        setResult({ submitted: items.length, created, failed: items.length - created, items })
        return
      }

      // Magnet / links bulk
      const lines = magnetLinks.split('\n').map(l => l.trim()).filter(Boolean)
      const res = await createBulkJobs({
        source_value: magnetLinks,
        provider_config_id: providerId,
        destination_config_id: destId,
        auto_start: true,
        send_to_destination: sendToDest,
      })
      const items: NewJobResultItem[] = res.jobs.map((entry, i) => ({
        id: entry.job?.id ?? `entry-${i}`,
        input: lines[i] ?? entry.job?.source_value ?? '',
        status: entry.error ? 'failed' : entry.reused ? 'reused' : 'created',
        jobId: entry.job?.id,
        error: entry.error ?? undefined,
      }))
      const created = items.filter(i => i.status !== 'failed').length
      setResult({ submitted: items.length, created, failed: items.length - created, items })
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : t('submissionFailed')
      const input = activeTab === 'torrent' ? (torrentFileName ?? 'torrent') : 'submission'
      setResult({ submitted: 1, created: 0, failed: 1, items: [{ id: 'err', input, status: 'failed', error: msg }] })
    } finally {
      setSubmitting(false)
    }
  }

  return {
    activeTab, setActiveTab,
    magnetLinks, setMagnetLinks,
    // Single-file compat
    torrentFile: torrentFiles[0] ?? null,
    torrentFileName,
    torrentFiles, setTorrentFiles,
    handleTorrentFile: (f: File | null) => setTorrentFiles(f ? [f] : []),
    handleTorrentFiles: (files: File[]) => setTorrentFiles(files),
    providers, destinations,
    providerId, setProviderId,
    destinationId, setDestinationId,
    linksOnly, setLinksOnly,
    advancedOpen, setAdvancedOpen,
    configsLoading, configsError,
    submitting, canSubmit,
    result, dismissResult: () => setResult(null),
    handleSubmit,
  }
}
