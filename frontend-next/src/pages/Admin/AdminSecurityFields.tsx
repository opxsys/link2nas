import SectionCard from '@/components/common/SectionCard'
import type { SecurityTokenTtl, SecurityPasswordPolicy } from './admin.types'

const NUM = 'h-9 w-24 rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const CHECK = 'h-4 w-4 rounded border-input accent-primary disabled:opacity-50'
const ROW = 'flex items-center justify-between gap-4'
const CHECK_ROW = 'flex items-center gap-2.5'
const FIELD_LABEL = 'text-sm text-foreground'
const UNIT = 'shrink-0 text-xs text-muted-foreground'

interface Props {
  tokenTtl: SecurityTokenTtl
  passwordPolicy: SecurityPasswordPolicy
  disabled?: boolean
  onTokenTtl: (key: keyof SecurityTokenTtl, value: number) => void
  onPasswordPolicy: (key: keyof SecurityPasswordPolicy, value: boolean | number) => void
}

const TTL_FIELDS: { key: keyof SecurityTokenTtl; label: string; unit: string; min: number; max: number }[] = [
  { key: 'invitation_ttl_hours',       label: 'Invitation token',         unit: 'hours',   min: 1,  max: 336 },
  { key: 'password_reset_ttl_hours',   label: 'Password reset token',     unit: 'hours',   min: 1,  max: 24  },
  { key: 'magic_login_ttl_minutes',    label: 'Magic login token',        unit: 'minutes', min: 5,  max: 120 },
  { key: 'email_verification_ttl_hours', label: 'Email verification token', unit: 'hours', min: 1,  max: 168 },
  { key: 'session_inactivity_minutes', label: 'Session inactivity',       unit: 'minutes', min: 5,  max: 1440 },
]

const POLICY_CHECKS: { key: keyof SecurityPasswordPolicy; label: string }[] = [
  { key: 'require_uppercase', label: 'Require uppercase letter' },
  { key: 'require_lowercase', label: 'Require lowercase letter' },
  { key: 'require_number',    label: 'Require number'           },
  { key: 'require_special',   label: 'Require special character' },
]

export default function AdminSecurityFields({ tokenTtl, passwordPolicy, disabled, onTokenTtl, onPasswordPolicy }: Props) {
  return (
    <div className="flex flex-col gap-4">
      <SectionCard title="Token & Session TTL" description="Expiration windows for tokens and inactive sessions.">
        <div className="flex flex-col gap-4">
          {TTL_FIELDS.map(({ key, label, unit, min, max }) => (
            <div key={key} className={ROW}>
              <label htmlFor={`sec-ttl-${key}`} className={FIELD_LABEL}>
                {label}
                <span className="ml-1.5 text-xs text-muted-foreground">({min}–{max} {unit})</span>
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
                <span className={UNIT}>{unit}</span>
              </div>
            </div>
          ))}
        </div>
      </SectionCard>

      <SectionCard title="Password Policy" description="Requirements enforced at account creation and password change.">
        <div className="flex flex-col gap-4">
          <div className={ROW}>
            <label htmlFor="sec-pw-min-length" className={FIELD_LABEL}>
              Minimum length
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
              <span className={UNIT}>chars</span>
            </div>
          </div>
          <div className="flex flex-col gap-2.5">
            {POLICY_CHECKS.map(({ key, label }) => (
              <div key={key} className={CHECK_ROW}>
                <input
                  id={`sec-pw-${key}`}
                  type="checkbox"
                  className={CHECK}
                  checked={passwordPolicy[key] as boolean}
                  disabled={disabled}
                  onChange={(e) => onPasswordPolicy(key, e.target.checked)}
                />
                <label htmlFor={`sec-pw-${key}`} className={FIELD_LABEL}>{label}</label>
              </div>
            ))}
          </div>
        </div>
      </SectionCard>
    </div>
  )
}
