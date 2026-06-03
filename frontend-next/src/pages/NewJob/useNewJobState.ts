import { useState, useEffect } from 'react'
import { listProviderConfigs } from '@/api/provider-configs'
import { listDestinationConfigs } from '@/api/destination-configs'
import { createBulkJobs, createTorrentJob } from '@/api/jobs'
import { ApiError } from '@/api/client'
import type { ProviderConfig } from '@/api/provider-configs'
import type { DestinationConfig } from '@/api/destination-configs'
import type { NewJobTab, NewJobResult, NewJobResultItem } from './newJob.types'

export function useNewJobState() {
  const [activeTab, setActiveTab] = useState<NewJobTab>('magnet')
  const [magnetLinks, setMagnetLinks] = useState('')
  const [torrentFile, setTorrentFile] = useState<File | null>(null)
  const [batchText, setBatchText] = useState('')

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
        const [prov, dest] = await Promise.all([
          listProviderConfigs(),
          listDestinationConfigs(),
        ])

        if (cancelled) return

        const enabledProv = prov.filter((p) => p.is_enabled)
        const enabledDest = dest.filter((d) => d.is_enabled)

        setProviders(enabledProv)
        setDestinations(enabledDest)

        const defaultProvider = enabledProv.find((p) => p.is_default) ?? enabledProv[0]
        const defaultDestination = enabledDest.find((d) => d.is_default)

        if (defaultProvider) {
          setProviderId(defaultProvider.id)
        } else {
          setProviderId('')
        }

        if (defaultDestination) {
          setDestinationId(defaultDestination.id)
          setLinksOnly(false)
        } else {
          setDestinationId('')
          setLinksOnly(true)
        }
      } catch (err) {
        if (!cancelled) {
          setConfigsError(
            err instanceof ApiError
              ? err.message
              : 'Failed to load providers/destinations.',
          )
        }
      } finally {
        if (!cancelled) {
          setConfigsLoading(false)
        }
      }
    }

    loadConfigs()

    return () => {
      cancelled = true
    }
  }, [])

  const canSubmit =
    !submitting &&
    !configsLoading &&
    !!providerId &&
    (
      (activeTab === 'magnet' && magnetLinks.trim().length > 0) ||
      (activeTab === 'torrent' && torrentFile !== null) ||
      (activeTab === 'batch' && batchText.trim().length > 0)
    )

  async function handleSubmit() {
    if (!canSubmit || !providerId) return

    setSubmitting(true)
    setResult(null)

    const destinationConfigId = linksOnly ? undefined : (destinationId || undefined)

    try {
      if (activeTab === 'torrent' && torrentFile) {
        const res = await createTorrentJob(torrentFile, {
          provider_config_id: providerId,
          destination_config_id: destinationConfigId,
          auto_start: true,
        })

        const item: NewJobResultItem = {
          id: res.job.id,
          input: torrentFile.name,
          status: res.error ? 'failed' : res.reused ? 'reused' : 'created',
          jobId: res.job.id,
          error: res.error ?? undefined,
        }

        setResult({
          submitted: 1,
          created: item.status !== 'failed' ? 1 : 0,
          failed: item.status === 'failed' ? 1 : 0,
          items: [item],
        })

        return
      }

      const raw = activeTab === 'magnet' ? magnetLinks : batchText
      const lines = raw
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean)

      const res = await createBulkJobs({
        source_value: raw,
        provider_config_id: providerId,
        destination_config_id: destinationConfigId,
        auto_start: true,
      })

      const items: NewJobResultItem[] = res.jobs.map((entry, index) => ({
        id: entry.job.id,
        input: lines[index] ?? entry.job.source_value,
        status: entry.error ? 'failed' : entry.reused ? 'reused' : 'created',
        jobId: entry.job.id,
        error: entry.error ?? undefined,
      }))

      const created = items.filter((item) => item.status !== 'failed').length

      setResult({
        submitted: items.length,
        created,
        failed: items.length - created,
        items,
      })
    } catch (err) {
      const message = err instanceof ApiError ? err.message : 'Submission failed.'

      const input =
        activeTab === 'torrent'
          ? torrentFile?.name ?? 'torrent file'
          : activeTab === 'magnet'
            ? 'magnet links'
            : 'batch'

      setResult({
        submitted: 1,
        created: 0,
        failed: 1,
        items: [
          {
            id: 'err',
            input,
            status: 'failed',
            error: message,
          },
        ],
      })
    } finally {
      setSubmitting(false)
    }
  }

  return {
    activeTab,
    setActiveTab,

    magnetLinks,
    setMagnetLinks,

    torrentFile,
    torrentFileName: torrentFile?.name ?? null,
    handleTorrentFile: (file: File | null) => setTorrentFile(file),

    batchText,
    setBatchText,

    providers,
    destinations,

    providerId,
    setProviderId,

    destinationId,
    setDestinationId,

    linksOnly,
    setLinksOnly,

    advancedOpen,
    setAdvancedOpen,

    configsLoading,
    configsError,

    submitting,
    canSubmit,

    result,
    dismissResult: () => setResult(null),

    handleSubmit,
  }
}
