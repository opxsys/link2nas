import { Link } from 'react-router-dom'
import { Settings } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { useI18n } from '@/i18n'
import type { NotificationRule, NotificationConfig } from './notifications.types'

const CHANNEL_LABEL: Record<string, string> = {
  email: 'Email', gotify: 'Gotify', webhook: 'Webhook',
}

const SEVERITY_LABEL: Record<string, string> = {
  info: 'Info+', warning: 'Warning+', error: 'Error+', critical: 'Critical only',
}

interface Props {
  rules: NotificationRule[]
  configs: NotificationConfig[]
  loading: boolean
  error: string | null
  onToggle: (id: string, enabled: boolean) => Promise<void>
}

function RuleRow({
  rule, configName, onToggle,
}: {
  rule: NotificationRule
  configName: string
  onToggle: () => void
}) {
  const { t } = useI18n()
  return (
    <tr className="border-b border-border last:border-0 hover:bg-muted/30">
      <td className="px-4 py-2.5 text-sm text-foreground">{rule.name}</td>
      <td className="px-4 py-2.5 text-xs font-mono text-muted-foreground">
        {rule.event_types.length
          ? rule.event_types.join(', ')
          : <span className="italic">{t('allEvents')}</span>}
      </td>
      <td className="px-4 py-2.5 text-sm text-muted-foreground">{configName}</td>
      <td className="px-4 py-2.5 text-xs text-muted-foreground">
        {SEVERITY_LABEL[rule.severity_min] ?? rule.severity_min}
      </td>
      <td className="px-4 py-2.5">
        <label className="flex cursor-pointer items-center gap-2">
          <input
            type="checkbox"
            checked={rule.is_enabled}
            onChange={onToggle}
            className="h-4 w-4 rounded border-input accent-primary"
            aria-label={`${rule.is_enabled ? t('ruleDisablePrefix') : t('ruleEnablePrefix')} ${rule.name}`}
          />
          <span className="text-xs text-muted-foreground">
            {rule.is_enabled ? t('toggleOn') : t('toggleOff')}
          </span>
        </label>
      </td>
    </tr>
  )
}

export default function NotificationRulesTable({ rules, configs, loading, error, onToggle }: Props) {
  const { t } = useI18n()

  function configName(configId: string): string {
    const cfg = configs.find(c => c.id === configId)
    return cfg ? `${cfg.name} (${CHANNEL_LABEL[cfg.channel] ?? cfg.channel})` : '—'
  }

  return (
    <SectionCard
      title={t('notifRulesTitle')}
      description={t('notifRulesDesc')}
      actions={
        <Link
          to="/settings?section=notifications"
          className="inline-flex items-center gap-1.5 rounded-md border border-border bg-background px-3 py-1.5 text-xs font-medium text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <Settings size={12} aria-hidden="true" />
          {t('notifManageSettings')}
        </Link>
      }
    >
      {loading && (
        <p className="py-6 text-sm text-muted-foreground">{t('notifLoadingRules')}</p>
      )}
      {!loading && error && (
        <p className="py-4 text-sm text-destructive">{error}</p>
      )}
      {!loading && !error && rules.length === 0 && (
        <p className="py-4 text-sm italic text-muted-foreground">
          {t('notifNoRulesText')}{' '}
          <Link to="/settings?section=notifications" className="underline hover:text-foreground">
            {t('notifAddSettingsLink')}
          </Link>
        </p>
      )}
      {!loading && !error && rules.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">{t('colRuleName')}</th>
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">{t('colRuleEvents')}</th>
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">{t('labelChannel')}</th>
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">{t('colRuleMinSev')}</th>
                <th className="px-4 py-2 text-xs font-medium text-muted-foreground">{t('colRuleEnabled')}</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <RuleRow
                  key={rule.id}
                  rule={rule}
                  configName={configName(rule.config_id)}
                  onToggle={() => onToggle(rule.id, !rule.is_enabled)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </SectionCard>
  )
}
