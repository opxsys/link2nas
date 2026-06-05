import { createContext, useContext, useState, useCallback, useEffect } from 'react'
import { listUserAnnouncements } from '@/api/announcements'
import type { UserAnnouncement } from '@/api/announcements'
import { subscribeAnnouncementsChanged } from '@/lib/announcementEvents'

function computeCount(items: UserAnnouncement[]): number {
  return items.filter(
    (a) =>
      a.user_status.read_at === null ||
      (a.require_acknowledgement && a.user_status.acknowledged_at === null),
  ).length
}

interface AnnouncementBadgeValue {
  count: number
  invalidate: () => void
}

const AnnouncementBadgeContext = createContext<AnnouncementBadgeValue>({
  count: 0,
  invalidate: () => {},
})

export function AnnouncementBadgeProvider({ children }: { children: React.ReactNode }) {
  const [count, setCount] = useState(0)
  const [tick, setTick] = useState(0)

  useEffect(() => {
    listUserAnnouncements()
      .then((items) => setCount(computeCount(items)))
      .catch(() => {})
  }, [tick])

  const invalidate = useCallback(() => setTick((t) => t + 1), [])

  // Respond to announcement mutations (admin create/edit/delete, user read/ack)
  useEffect(() => subscribeAnnouncementsChanged(invalidate), [invalidate])

  return (
    <AnnouncementBadgeContext.Provider value={{ count, invalidate }}>
      {children}
    </AnnouncementBadgeContext.Provider>
  )
}

export function useAnnouncementBadge(): AnnouncementBadgeValue {
  return useContext(AnnouncementBadgeContext)
}
