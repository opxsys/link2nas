import SectionCard from '@/components/common/SectionCard'
import type { SecurityTokenTtl, SecurityPasswordPolicy } from './admin.types'
import { useI18n } from '@/i18n'
import type { TranslationKey } from '@/i18n'

const NUM = 'h-9 w-24 rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const CHECK = 'h-4 w-4 rounded border-input accent-primary disabled:opacity-50'
const ROW = 'flex items-center justify-between gap-4'
const CHECK_ROW = 'flex items-center gap-2.5'
const FIELD_LABEL = 'text-sm text-foreground'
const UNIT = 'shrink-0 text-xs text-muted-foreground'

const SINGLE_USER_HIDDEN_TTL = new Set<keyof SecurityTokenTtl>([
  'invitation_ttl_hours',
  'password_reset_ttl_hours',
  'magic_login_ttl_minutes',
  'email_verification_ttl_hours',
])

interface Props {
  tokenTtl: SecurityTokenTtl
  passwordPolicy: SecurityPasswordPolicy
  disabled?: boolean
  singleUserMode?: boolean
  onTokenTtl: (key: keyof SecurityTokenTtl, value: number) => void
  onPasswordPolicy: (key: keyof SecurityPasswordPolicy, value: boolean | number) => void
}

export default function AdminSecurityFields({ tokenTtl, passwordPolicy, disabled, singleUserMode, onTokenTtl, onPasswordPolicy }: Props) {
  const { t } = useI18n()

  const ALL_TTL_FIELDS: { key: keyof SecurityTokenTtl; labelKey: TranslationKey; unitKey: TranslationKey; min: number; max: number }[] = [
    { key: 'invitation_ttl_hours',         labelKey: 'adminInvitationTtl',    unitKey: 'unitHours',   min: 1,  max: 336  },
    { key: 'password_reset_ttl_hours',     labelKey: 'adminPwResetTtl',       unitKey: 'unitHours',   min: 1,  max: 24   },
    { key: 'magic_login_ttl_minutes',      labelKey: 'adminMagicLoginTtl',    unitKey: 'unitMinutes', min: 5,  max: 120  },
    { key: 'email_verification_ttl_hours', labelKey: 'adminEmailVerifTtl',    unitKey: 'unitHours',   min: 1,  max: 168  },
    { key: 'session_inactivity_minutes',   labelKey: 'adminSessionInactivity',unitKey: 'unitMinutes', min: 5,  max: 1440 },
  ]

  const TTL_FIELDS = singleUserMode
    ? ALL_TTL_FIELDS.filter((f) => !SINGLE_USER_HIDDEN_TTL.has(f.key))
    : ALL_TTL_FIELDS

  const POLICY_CHECKS: { key: keyof SecurityPasswordPolicy; labelKey: TranslationKey }[] = [
    { key: 'require_uppercase', labelKey: 'adminReqUppercase' },
    { key: 'require_lowercase', labelKey: 'adminReqLowercase' },
    { key: 'require_number',    labelKey: 'adminReqNumber'    },
    { key: 'require_special',   labelKey: 'adminReqSpecial'   },
  ]

  return (
    <div className="flex flex-col gap-4">
      <SectionCard title={t('adminTtlTitle')} description={t('adminTtlDesc')}>
        <div className="flex flex-col gap-4">
          {TTL_FIELDS.map(({ key, labelKey, unitKey, min, max }) => (
            <div key={key} className={ROW}>
              <label htmlFor={`sec-ttl-${key}`} className={FIELD_LABEL}>
                {t(labelKey)}
                <span className="ml-1.5 text-xs text-muted-foreground">({min}–{max} {t(unitKey)})</span>
              </label>
              <div className="flex shrink-0 items-center gap-2">
                <input
                  id={`sec-ttl-${key}`}
                  type="number"
                  className={NUM}
                  value={tokenTtl[key]}
                  disabled={disabled}
                  min={min}
                  max={max}
                  onChange={(e) => onTokenTtl(key, Number(e.target.value))}
                />
                <span className={UNIT}>{t(unitKey)}</span>
              </div>
            </div>
          ))}
        </div>
      </SectionCard>

      <SectionCard title={t('adminPwPolicyTitle')} description={t('adminPwPolicyDesc')}>
        <div className="flex flex-col gap-4">
          <div className="flex items-center gap-3">
            <label htmlFor="sec-pw-min-length" className={FIELD_LABEL}>
              {t('adminMinLengthLabel')}
              <span className="ml-1.5 text-xs text-muted-foreground">(8–128)</span>
            </label>
            <div className="flex shrink-0 items-center gap-2">
              <input
                id="sec-pw-min-length"
                type="number"
                className={NUM}
                value={passwordPolicy.min_length}
                disabled={disabled}
                min={8}
                max={128}
                onChange={(e) => onPasswordPolicy('min_length', Number(e.target.value))}
              />
              <span className={UNIT}>{t('adminPwChars')}</span>
            </div>
          </div>
          <div className="grid grid-cols-1 gap-x-6 gap-y-1.5 sm:grid-cols-2">
            {POLICY_CHECKS.map(({ key, labelKey }) => (
              <div key={key} className={CHECK_ROW}>
                <input
                  id={`sec-pw-${key}`}
                  type="checkbox"
                  className={CHECK}
                  checked={passwordPolicy[key] as boolean}
                  disabled={disabled}
                  onChange={(e) => onPasswordPolicy(key, e.target.checked)}
                />
                <label htmlFor={`sec-pw-${key}`} className={FIELD_LABEL}>{t(labelKey)}</label>
              </div>
            ))}
          </div>
        </div>
      </SectionCard>
    </div>
  )
}
