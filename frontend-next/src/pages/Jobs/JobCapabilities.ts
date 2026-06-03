/**
 * Port of frontend/js/render/jobs/actions/capabilities.js
 * Derives what actions are visible/available for a given job.
 */
import type { RealJob, RealJobDestinationConfig, RealJobProviderConfig } from '@/api/jobs'

function normalizeDestName(v: string | null | undefined): string {
  const s = String(v ?? '').trim().toLowerCase()
  if (s === 'nas') return 'synology'
  return s
}

export function getActiveDestinations(job: RealJob): RealJobDestinationConfig[] {
  return (job.active_real_destination_configs ?? []).filter(
    c => c?.id && ['synology', 'local', 'nas'].includes(
      normalizeDestName(c.destination_type ?? c.destination_name)
    )
  )
}

export function getOtherProviders(job: RealJob): RealJobProviderConfig[] {
  const all = job.active_provider_configs ?? []
  return all.filter(c => c?.id && c.id !== job.provider_config_id)
}

export interface JobCapabilities {
  canStart:                  boolean
  canRestart:                boolean
  canCancel:                 boolean
  canRefresh:                boolean
  canSelectFiles:            boolean
  canUnrestrict:             boolean
  canCopySingle:             boolean
  canCopyAll:                boolean
  canSendDirect:             boolean   // send to current/only destination
  canChooseSendDest:         boolean   // no current dest, multiple available
  canResend:                 boolean   // resend to same destination
  canSendOtherDest:          boolean   // send to a different destination
  canCloneWithProvider:      boolean
  canCancelLocalDownload:    boolean
  canDelete:                 boolean   // always true
  hasAnyDestination:         boolean   // at least one real dest config active
  activeDestinations:        RealJobDestinationConfig[]
  otherProviders:            RealJobProviderConfig[]
}

export function getJobCapabilities(job: RealJob): JobCapabilities {
  const status = String(job.status ?? '').trim().toLowerCase()
  const allowed = job.allowed_actions ?? []
  const can = (a: string) => allowed.includes(a)

  const readyStatuses = ['ready', 'partially_ready', 'completed']
  const isReady = readyStatuses.includes(status)

  const activeDestinations = getActiveDestinations(job)
  const otherProviders = getOtherProviders(job)

  const hasAnyDestination = activeDestinations.length > 0
  const hasCurrentDest = !!(job.destination_config_id || normalizeDestName(job.destination_name || job.destination_type))
  const hasOneDest = activeDestinations.length === 1
  const hasMultiDest = activeDestinations.length > 1

  const currentDestId = job.destination_config_id
  const destAvail = Boolean(job.destination_available)

  // Send-to-destination: job is ready, not yet sent, has a dest configured or exactly one active
  const canSendDirect = isReady && hasAnyDestination && !job.sent_to_destination && (hasCurrentDest || hasOneDest)

  // No current destination, multiple available → choose
  const canChooseSendDest = isReady && hasAnyDestination && !job.sent_to_destination && !hasCurrentDest && hasMultiDest

  // Resend to same destination: already sent, destination still available
  const canResend = isReady && hasAnyDestination && job.sent_to_destination && !!currentDestId && destAvail

  // Send to a different destination (already sent or has current, and alternatives exist)
  const canSendOtherDest = isReady && (job.sent_to_destination || hasCurrentDest) &&
    activeDestinations.some(d => d.id !== currentDestId)

  // Cancel local download
  const destStatus = String(job.destination_status ?? '').trim().toLowerCase()
  const destName = normalizeDestName(job.destination_name || job.destination_type)
  const canCancelLocalDownload = destName === 'local' &&
    ['queued', 'sending', 'downloading', 'cancel_requested'].includes(destStatus) &&
    !job.sent_to_destination

  // Clone with other provider
  const canCloneWithProvider = Boolean(job.can_clone_with_other_provider) &&
    Boolean(job.provider_available) &&
    otherProviders.length > 0 &&
    ['created', 'failed', 'cancelled', 'ready', 'partially_ready', 'completed'].includes(status)

  // Copy links
  const canCopySingle = !!job.download_url && job.output_mode !== 'per_file'
  const canCopyAll = job.output_mode === 'per_file' && (job.files ?? []).some(f => f.download_url)

  // Unrestrict: global unrestrict when job is downloaded/ready/completed and has debrid link
  const canUnrestrict = can('unrestrict') || (
    ['downloaded', 'ready', 'completed'].includes(status) &&
    job.output_mode !== 'per_file' &&
    (!!job.debrid_link || (job.source_type === 'direct_link' && !!job.source_value))
  )

  return {
    canStart:               can('start'),
    canRestart:             can('restart'),
    canCancel:              can('cancel'),
    canRefresh:             can('refresh'),
    canSelectFiles:         can('select_files'),
    canUnrestrict,
    canCopySingle,
    canCopyAll,
    canSendDirect,
    canChooseSendDest,
    canResend,
    canSendOtherDest,
    canCloneWithProvider,
    canCancelLocalDownload,
    canDelete:              true,
    hasAnyDestination,
    activeDestinations,
    otherProviders,
  }
}
