import { useState, useEffect, useCallback, useRef } from 'react'
import { AlertTriangle, CheckCircle2, Loader2, Plus, X } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import {
  listNotificationConfigs, listNotificationRules,
  deleteNotificationConfig, deleteNotificationRule,
} from '@/api/notifications'
import { ApiError } from '@/api/client'
import type { NotificationConfig, NotificationRule } from '@/pages/Notifications/notifications.types'
import { useI18n } from '@/i18n'
import NotifChannelRow from './NotifChannelRow'
import NotifRuleRow from './NotifRuleRow'
import NotifChannelModal from './NotifChannelModal'
import NotifRuleModal from './NotifRuleModal'
import NotifDeleteModal from './NotifDeleteModal'
import { useMe } from '@/lib/useMe'

type ChannelModal = { open: false } | { open: true; editing: NotificationConfig | null }
type RuleModal    = { open: false } | { open: true; editing: NotificationRule | null }
type DeleteTarget =
  | { open: false }
  | { open: true; kind: 'config'; item: NotificationConfig }
  | { open: true; kind: 'rule';   item: NotificationRule }

export default function NotificationSettings() {
  const { t } = useI18n()
  const [configs, setConfigs] = useState<NotificationConfig[]>([])
  const [rules, setRules] = useState<NotificationRule[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [channelModal, setChannelModal] = useState<ChannelModal>({ open: false })
  const [ruleModal, setRuleModal] = useState<RuleModal>({ open: false })
  const [deleteTarget, setDeleteTarget] = useState<DeleteTarget>({ open: false })
  const [successMessage, setSuccessMessage] = useState<string | null>(null)
  const successTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const { me } = useMe()
  const smtpEnabled: boolean | null = me !== null ? (me.email_sending_available ?? null) : null

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [cfgs, rlz] = await Promise.all([listNotificationConfigs(), listNotificationRules()])
      setConfigs(cfgs)
      setRules(rlz)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('notifLoadFailed'))
    } finally {
      setLoading(false)
    }
  }, [t])

  useEffect(() => { load() }, [load])

  useEffect(() => () => { if (successTimer.current) clearTimeout(successTimer.current) }, [])

  function showSuccess(msg: string) {
    if (successTimer.current) clearTimeout(successTimer.current)
    setSuccessMessage(msg)
    successTimer.current = setTimeout(() => setSuccessMessage(null), 4000)
  }

  function handleConfigSaved(_cfg: NotificationConfig) {
    load()
    showSuccess(t('channelSaved'))
  }

  function handleRuleSaved(rule: NotificationRule) {
    setRules(prev => {
      const idx = prev.findIndex(r => r.id === rule.id)
      return idx >= 0 ? prev.map(r => r.id === rule.id ? rule : r) : [...prev, rule]
    })
  }

  async function handleDeleteConfirm() {
    if (!deleteTarget.open) return
    if (deleteTarget.kind === 'config') {
      const linked = rules.filter(r => r.config_id === deleteTarget.item.id)
      for (const rule of linked) {
        await deleteNotificationRule(rule.id)
      }
      await deleteNotificationConfig(deleteTarget.item.id)
      await load()
      showSuccess(t('channelDeleted'))
    } else {
      await deleteNotificationRule(deleteTarget.item.id)
      setRules(prev => prev.filter(r => r.id !== deleteTarget.item.id))
      showSuccess(t('ruleDeleted'))
    }
  }

  function deleteDescription(): string {
    if (!deleteTarget.open) return ''
    if (deleteTarget.kind === 'rule') return `${t('deleteRuleConfirmPre')} "${deleteTarget.item.name}"${t('deleteConfirmPost')}`
    return `${t('deleteChannelConfirmPre')} "${deleteTarget.item.name}"${t('deleteConfirmPost')}`
  }

  function deleteLinkedCount(): number {
    if (!deleteTarget.open || deleteTarget.kind !== 'config') return 0
    return rules.filter(r => r.config_id === deleteTarget.item.id).length
  }

  const smtpDisabled = smtpEnabled === false
  const hasEmailConfig = configs.some(c => c.channel === 'email')

  return (
    <div className="flex flex-col gap-6">
      {successMessage && (
        <div className="flex items-center justify-between gap-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2.5 text-sm text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-400">
          <span className="flex items-center gap-2">
            <CheckCircle2 size={14} aria-hidden="true" />
            {successMessage}
          </span>
          <button onClick={() => setSuccessMessage(null)} className="shrink-0 opacity-60 hover:opacity-100" aria-label={t('dismiss')}>
            <X size={14} aria-hidden="true" />
          </button>
        </div>
      )}

      <SectionCard
        title={t('sectionChannels')}
        description={t('channelsDesc')}
        actions={
          <Button variant="outline" size="sm"
            onClick={() => setChannelModal({ open: true, editing: null })}>
            <Plus size={13} className="mr-1.5" aria-hidden="true" /> {t('addChannel')}
          </Button>
        }
      >
        {loading && (
          <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
            <Loader2 size={14} className="animate-spin" aria-hidden="true" /> {t('loading')}
          </div>
        )}
        {!loading && error && (
          <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
            {error}
          </div>
        )}
        {!loading && !error && smtpDisabled && hasEmailConfig && (
          <div className="mb-3 flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2.5 text-sm text-amber-700 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-400">
            <AlertTriangle size={14} className="mt-0.5 shrink-0" aria-hidden="true" />
            {t('smtpDisabledChannelWarning')}
          </div>
        )}
        {!loading && !error && configs.length === 0 && (
          <p className="py-4 text-sm italic text-muted-foreground">{t('noChannels')}</p>
        )}
        {!loading && !error && configs.length > 0 && (
          <div className="flex flex-col gap-2">
            {configs.map(cfg => (
              <NotifChannelRow
                key={cfg.id} config={cfg} smtpEnabled={smtpEnabled}
                onEdit={() => setChannelModal({ open: true, editing: cfg })}
                onDelete={() => setDeleteTarget({ open: true, kind: 'config', item: cfg })}
              />
            ))}
          </div>
        )}
      </SectionCard>

      <SectionCard
        title={t('sectionRules')}
        description={t('rulesDesc')}
        actions={
          <Button variant="outline" size="sm" disabled={configs.length === 0}
            title={configs.length === 0 ? t('addChannelFirst') : undefined}
            onClick={() => setRuleModal({ open: true, editing: null })}>
            <Plus size={13} className="mr-1.5" aria-hidden="true" /> {t('addRule')}
          </Button>
        }
      >
        {!loading && !error && rules.length === 0 && (
          <p className="py-4 text-sm italic text-muted-foreground">
            {configs.length === 0 ? `${t('addChannelFirst')}.` : t('noRules')}
          </p>
        )}
        {!loading && !error && rules.length > 0 && (
          <div className="flex flex-col gap-2">
            {rules.map(rule => (
              <NotifRuleRow
                key={rule.id} rule={rule} configs={configs} emailBlocked={smtpDisabled}
                onEdit={() => setRuleModal({ open: true, editing: rule })}
                onDelete={() => setDeleteTarget({ open: true, kind: 'rule', item: rule })}
                onToggled={handleRuleSaved}
              />
            ))}
          </div>
        )}
      </SectionCard>

      {channelModal.open && (
        <NotifChannelModal
          editing={channelModal.editing} smtpEnabled={smtpEnabled}
          onClose={() => setChannelModal({ open: false })}
          onSaved={handleConfigSaved}
        />
      )}
      {ruleModal.open && (
        <NotifRuleModal
          editing={ruleModal.editing} configs={configs}
          onClose={() => setRuleModal({ open: false })}
          onSaved={handleRuleSaved}
        />
      )}
      {deleteTarget.open && (
        <NotifDeleteModal
          title={deleteTarget.kind === 'config' ? t('deleteChannelTitle') : t('deleteRuleTitle')}
          description={deleteDescription()}
          linkedCount={deleteLinkedCount()}
          onClose={() => setDeleteTarget({ open: false })}
          onConfirm={handleDeleteConfirm}
        />
      )}
    </div>
  )
}
