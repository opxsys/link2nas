import { useState } from 'react'
import { MOCK_PROVIDERS, MOCK_DESTINATIONS, createFakeResult } from './newJob.mock'
import type { NewJobTab, NewJobResult } from './newJob.types'

export function useNewJobState() {
  const [activeTab, setActiveTab] = useState<NewJobTab>('magnet')
  const [magnetLinks, setMagnetLinks] = useState('')
  const [torrentFileName, setTorrentFileName] = useState<string | null>(null)
  const [batchText, setBatchText] = useState('')
  const [providerId, setProviderId] = useState(MOCK_PROVIDERS[0].id)
  const [destinationId, setDestinationId] = useState(MOCK_DESTINATIONS[0].id)
  const [linksOnly, setLinksOnly] = useState(false)
  const [advancedOpen, setAdvancedOpen] = useState(false)
  const [result, setResult] = useState<NewJobResult | null>(null)

  const canSubmit =
    (activeTab === 'magnet' && magnetLinks.trim().length > 0) ||
    (activeTab === 'torrent' && torrentFileName !== null) ||
    (activeTab === 'batch' && batchText.trim().length > 0)

  function handleTorrentFile(file: File | null) {
    setTorrentFileName(file?.name ?? null)
  }

  function handleSubmit() {
    let inputs: string[] = []
    if (activeTab === 'magnet') {
      inputs = magnetLinks.split('\n').map((l) => l.trim()).filter(Boolean)
    } else if (activeTab === 'torrent') {
      inputs = torrentFileName ? [torrentFileName] : []
    } else {
      inputs = batchText.split('\n').map((l) => l.trim()).filter(Boolean)
    }
    if (inputs.length === 0) return
    setResult(createFakeResult(inputs))
  }

  function dismissResult() {
    setResult(null)
  }

  return {
    activeTab,
    setActiveTab,
    magnetLinks,
    setMagnetLinks,
    torrentFileName,
    handleTorrentFile,
    batchText,
    setBatchText,
    providerId,
    setProviderId,
    destinationId,
    setDestinationId,
    linksOnly,
    setLinksOnly,
    advancedOpen,
    setAdvancedOpen,
    result,
    dismissResult,
    handleSubmit,
    canSubmit,
    providers: MOCK_PROVIDERS,
    destinations: MOCK_DESTINATIONS,
  }
}
