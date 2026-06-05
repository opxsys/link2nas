import { useState, useEffect, useCallback, useRef } from 'react'
import { AlertTriangle, CheckCircle2, Loader2, Plus, X } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import {
  listNotificationConfigs, listNotificationRules,
  deleteNotificationConfig, deleteNotificationRule,
} from '@/api/notifications'
import { getSmtpSettings } from '@/api/admin-smtp'
import { ApiError } from '@/api/client'
import type { NotificationConfig, NotificationRule } from '@/pages/Notifications/notifications.types'
import NotifChannelRow from './NotifChannelRow'
import NotifRuleRow from './NotifRuleRow'
import NotifChannelModal from './NotifChannelModal'
import NotifRuleModal from './NotifRuleModal'
import NotifDeleteModal from './NotifDeleteModal'

type ChannelModal = { open: false } | { open: true; editing: NotificationConfig | null }
type RuleModal    = { open: false } | { open: true; editing: NotificationRule | null }
type DeleteTarget =
  | { open: false }
  | { open: true; kind: 'config'; item: NotificationConfig }
  | { open: true; kind: 'rule';   item: NotificationRule }

export default function NotificationSettings() {
  const [configs, setConfigs] = useState<NotificationConfig[]>([])
  const [rules, setRules] = useState<NotificationRule[]>([])
  const [smtpEnabled, setSmtpEnabled] = useState<boolean | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [channelModal, setChannelModal] = useState<ChannelModal>({ open: false })
  const [ruleModal, setRuleModal] = useState<RuleModal>({ open: false })
  const [deleteTarget, setDeleteTarget] = useState<DeleteTarget>({ open: false })
  const [successMessage, setSuccessMessage] = useState<string | null>(null)
  const successTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [cfgs, rlz] = await Promise.all([listNotificationConfigs(), listNotificationRules()])
      setConfigs(cfgs)
      setRules(rlz)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load notification settings.')
    } finally {
      setLoading(false)
    }
    try {
      const smtp = await getSmtpSettings()
      setSmtpEnabled(smtp.enabled && !!smtp.host)
    } catch { /* non-admin: stays null (unknown) */ }
  }, [])

  useEffect(() => { load() }, [load])

  useEffect(() => () => { if (successTimer.current) clearTimeout(successTimer.current) }, [])

  function showSuccess(msg: string) {
    if (successTimer.current) clearTimeout(successTimer.current)
    setSuccessMessage(msg)
    successTimer.current = setTimeout(() => setSuccessMessage(null), 4000)
  }

  function handleConfigSaved(_cfg: NotificationConfig) {
    // Always reload: backend may have cleared is_default on other configs of the same channel type
    load()
    showSuccess('Channel saved.')
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
      // Delete linked rules first — backend does not cascade, leaving orphans otherwise
      const linked = rules.filter(r => r.config_id === deleteTarget.item.id)
      for (const rule of linked) {
        await deleteNotificationRule(rule.id)
      }
      await deleteNotificationConfig(deleteTarget.item.id)
      // Reload to get authoritative state (also fixes default display)
      await load()
      showSuccess('Channel deleted.')
    } else {
      await deleteNotificationRule(deleteTarget.item.id)
      setRules(prev => prev.filter(r => r.id !== deleteTarget.item.id))
      showSuccess('Rule deleted.')
    }
  }

  function deleteDescription(): string {
    if (!deleteTarget.open) return ''
    if (deleteTarget.kind === 'rule') {
      return `Delete rule "${deleteTarget.item.name}"? This cannot be undone.`
    }
    const linked = rules.filter(r => r.config_id === deleteTarget.item.id)
    if (linked.length === 0) {
      return `Delete channel "${deleteTarget.item.name}"? This cannot be undone.`
    }
    const names = linked.map(r => r.name).join(', ')
    return `Delete channel "${deleteTarget.item.name}"? ${linked.length} linked rule${linked.length > 1 ? 's' : ''} will also be deleted: ${names}.`
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
          <button onClick={() => setSuccessMessage(null)} className="shrink-0 opacity-60 hover:opacity-100" aria-label="Dismiss">
            <X size={14} aria-hidden="true" />
          </button>
        </div>
      )}

      {/* Channels */}
      <SectionCard
        title="Notification Channels"
        description="Delivery endpoints: email, Gotify, or webhook."
        actions={
          <Button variant="outline" size="sm"
            onClick={() => setChannelModal({ open: true, editing: null })}>
            <Plus size={13} className="mr-1.5" aria-hidden="true" /> Add channel
          </Button>
        }
      >
        {loading && (
          <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
            <Loader2 size={14} className="animate-spin" aria-hidden="true" /> Loading…
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
            SMTP is not configured or disabled — email channels are unavailable.
          </div>
        )}
        {!loading && !error && configs.length === 0 && (
          <p className="py-4 text-sm italic text-muted-foreground">No channels configured yet.</p>
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

      {/* Rules */}
      <SectionCard
        title="Notification Rules"
        description="Define when and via which channel you are notified."
        actions={
          <Button variant="outline" size="sm" disabled={configs.length === 0}
            title={configs.length === 0 ? 'Add a channel first' : undefined}
            onClick={() => setRuleModal({ open: true, editing: null })}>
            <Plus size={13} className="mr-1.5" aria-hidden="true" /> Add rule
          </Button>
        }
      >
        {!loading && !error && rules.length === 0 && (
          <p className="py-4 text-sm italic text-muted-foreground">
            {configs.length === 0 ? 'Add a channel first.' : 'No rules configured yet.'}
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

      {/* Modals */}
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
          title={deleteTarget.kind === 'config' ? 'Delete channel' : 'Delete rule'}
          description={deleteDescription()}
          onClose={() => setDeleteTarget({ open: false })}
          onConfirm={handleDeleteConfirm}
        />
      )}
    </div>
  )
}
