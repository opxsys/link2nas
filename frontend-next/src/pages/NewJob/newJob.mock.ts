import type { MockProvider, MockDestination, NewJobResult, NewJobResultItem } from './newJob.types'

export const MOCK_PROVIDERS: MockProvider[] = [
  { id: 'rd-perso', name: 'Real-Debrid (perso)' },
  { id: 'alldebrid', name: 'AllDebrid' },
]

export const MOCK_DESTINATIONS: MockDestination[] = [
  { id: 'nas-maison', name: 'NAS Maison' },
  { id: 'nas-backup', name: 'NAS Backup' },
]

/**
 * Generates a deterministic fake result for visual testing.
 * When multiple inputs are given the last one always fails, to exercise the
 * mixed-state view in CreationResultPanel.
 */
export function createFakeResult(inputs: string[]): NewJobResult {
  const items: NewJobResultItem[] = inputs.map((input, index) => {
    const shouldFail = inputs.length > 1 && index === inputs.length - 1
    if (shouldFail) {
      return {
        id: String(index),
        input,
        status: 'failed',
        error: 'Provider could not resolve this link',
      }
    }
    return {
      id: String(index),
      input,
      status: 'created',
      jobId: `job-${String(index + 1).padStart(3, '0')}`,
    }
  })

  return {
    submitted: items.length,
    created: items.filter((i) => i.status === 'created').length,
    failed: items.filter((i) => i.status === 'failed').length,
    items,
  }
}
