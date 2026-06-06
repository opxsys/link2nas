import { useI18n } from '@/i18n'

const LABEL = 'mb-1.5 block text-xs font-medium text-foreground'
const INPUT = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const CHECK_ROW = 'flex items-center gap-2.5'
const CHECK = 'h-4 w-4 rounded border-input accent-primary disabled:opacity-50'

export interface SmtpFields {
  enabled: boolean
  host: string
  port: number
  username: string
  password: string
  fromEmail: string
  fromName: string
  useTls: boolean
  useSsl: boolean
  hasPassword: boolean
}

interface Props {
  fields: SmtpFields
  disabled?: boolean
  onChange: <K extends keyof SmtpFields>(key: K, value: SmtpFields[K]) => void
}

export default function AdminSmtpFields({ fields, disabled, onChange }: Props) {
  const { t } = useI18n()
  return (
    <div className="flex flex-col gap-5">
      <div className={CHECK_ROW}>
        <input
          id="smtp-enabled"
          type="checkbox"
          className={CHECK}
          checked={fields.enabled}
          disabled={disabled}
          onChange={(e) => onChange('enabled', e.target.checked)}
        />
        <label htmlFor="smtp-enabled" className="text-sm text-foreground">
          {t('adminSmtpEnableLabel')}
        </label>
      </div>

      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
        <div>
          <label htmlFor="smtp-host" className={LABEL}>{t('adminSmtpHostLabel')}</label>
          <input
            id="smtp-host"
            type="text"
            className={INPUT}
            value={fields.host}
            disabled={disabled}
            placeholder="smtp.example.com"
            onChange={(e) => onChange('host', e.target.value)}
          />
        </div>
        <div>
          <label htmlFor="smtp-port" className={LABEL}>{t('adminSmtpPortLabel')}</label>
          <input
            id="smtp-port"
            type="number"
            className={INPUT}
            value={fields.port}
            disabled={disabled}
            min={1}
            max={65535}
            onChange={(e) => onChange('port', Number(e.target.value))}
          />
        </div>
      </div>

      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
        <div>
          <label htmlFor="smtp-username" className={LABEL}>{t('labelUsername')}</label>
          <input
            id="smtp-username"
            type="text"
            className={INPUT}
            value={fields.username}
            disabled={disabled}
            autoComplete="off"
            onChange={(e) => onChange('username', e.target.value)}
          />
        </div>
        <div>
          <label htmlFor="smtp-password" className={LABEL}>{t('password')}</label>
          <input
            id="smtp-password"
            type="password"
            className={INPUT}
            value={fields.password}
            disabled={disabled}
            autoComplete="new-password"
            placeholder={fields.hasPassword ? t('adminSmtpPasswordHint') : ''}
            onChange={(e) => onChange('password', e.target.value)}
          />
        </div>
      </div>

      <div className="grid grid-cols-1 gap-5 sm:grid-cols-2">
        <div>
          <label htmlFor="smtp-from-email" className={LABEL}>{t('adminSmtpFromEmailLabel')}</label>
          <input
            id="smtp-from-email"
            type="email"
            className={INPUT}
            value={fields.fromEmail}
            disabled={disabled}
            placeholder="noreply@example.com"
            onChange={(e) => onChange('fromEmail', e.target.value)}
          />
        </div>
        <div>
          <label htmlFor="smtp-from-name" className={LABEL}>{t('adminSmtpFromNameLabel')}</label>
          <input
            id="smtp-from-name"
            type="text"
            className={INPUT}
            value={fields.fromName}
            disabled={disabled}
            placeholder="Link2NAS"
            onChange={(e) => onChange('fromName', e.target.value)}
          />
        </div>
      </div>

      <div className="flex flex-wrap gap-6">
        <div className={CHECK_ROW}>
          <input
            id="smtp-use-tls"
            type="checkbox"
            className={CHECK}
            checked={fields.useTls}
            disabled={disabled}
            onChange={(e) => {
              onChange('useTls', e.target.checked)
              if (e.target.checked) onChange('useSsl', false)
            }}
          />
          <label htmlFor="smtp-use-tls" className="text-sm text-foreground">{t('adminSmtpStarttls')}</label>
        </div>
        <div className={CHECK_ROW}>
          <input
            id="smtp-use-ssl"
            type="checkbox"
            className={CHECK}
            checked={fields.useSsl}
            disabled={disabled}
            onChange={(e) => {
              onChange('useSsl', e.target.checked)
              if (e.target.checked) onChange('useTls', false)
            }}
          />
          <label htmlFor="smtp-use-ssl" className="text-sm text-foreground">{t('adminSmtpSslLabel')}</label>
        </div>
      </div>
      <p className="text-xs text-muted-foreground">{t('adminSmtpTlsExclusive')}</p>
    </div>
  )
}
