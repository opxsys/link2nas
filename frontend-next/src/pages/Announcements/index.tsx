import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus } from 'lucide-react'
import PageHeader from '@/components/layout/PageHeader'
import { Button } from '@/components/ui/button'
import { getMe } from '@/api/me'
import { useI18n } from '@/i18n'
import AnnouncementsUserView from './AnnouncementsUserView'

export default function AnnouncementsPage() {
  const { t } = useI18n()
  const [isSuperAdmin, setIsSuperAdmin] = useState(false)
  const navigate = useNavigate()

  useEffect(() => {
    getMe()
      .then((me) => setIsSuperAdmin(me.role === 'super_admin'))
      .catch(() => {})
  }, [])

  return (
    <>
      <PageHeader
        title={t('navAnnouncements')}
        description={t('announcementsDesc')}
        actions={
          isSuperAdmin ? (
            <Button
              size="sm"
              variant="outline"
              onClick={() => navigate('/admin?section=announcements&action=create')}
            >
              <Plus size={13} className="mr-1.5" aria-hidden="true" />
              {t('createAnnouncement')}
            </Button>
          ) : undefined
        }
      />
      <AnnouncementsUserView />
    </>
  )
}
