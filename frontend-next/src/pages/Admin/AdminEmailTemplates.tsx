import { useState, useEffect, useCallback, useRef } from 'react'
import { Loader2, AlertCircle, CheckCircle2, XCircle, AlertTriangle, RotateCcw, X, Eye } from 'lucide-react'
import SectionCard from '@/components/common/SectionCard'
import { Button } from '@/components/ui/button'
import { getEmailTemplate, saveEmailTemplate, resetEmailTemplate, previewEmailTemplate } from '@/api/admin-email-templates'
import { ApiError } from '@/api/client'
import { useSmtpStatus } from '@/lib/useSmtpStatus'
import type { EmailTemplate, EmailTemplatePreview } from '@/api/admin-email-templates'
import AdminEmailTemplatePreview from './AdminEmailTemplatePreview'
import { useI18n } from '@/i18n'

const INPUT    = 'h-9 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'
const LABEL    = 'mb-1.5 block text-xs font-medium text-foreground'
const TEXTAREA = 'w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50'

export default function AdminEmailTemplates() {
  const { t } = useI18n()
  const { smtpAvailable, smtpLoading } = useSmtpStatus()

  const TEMPLATE_KEYS = [
    { value: 'invitation',         label: t('adminTplKeyInvitation')    },
    { value: 'password_reset',     label: t('adminTplKeyPasswordReset') },
    { value: 'email_verification', label: t('adminTplKeyEmailVerif')    },
    { value: 'magic_login',        label: t('adminTplKeyMagicLogin')    },
    { value: 'smtp_test',          label: t('adminTplKeySmtpTest')      },
    { value: 'announcement',       label: t('adminTplKeyAnnouncement')  },
    { value: 'notification_event', label: t('adminTplKeyNotifEvent')    },
    { value: 'notification_test',  label: t('adminTplKeyNotifTest')     },
  ]

  const LANGUAGES = [
    { value: 'en', label: t('langEnglish') },
    { value: 'fr', label: t('langFrench') },
  ]

  const [selectedKey, setSelectedKey] = useState('invitation')
  const [selectedLang, setSelectedLang] = useState('en')
  const [template, setTemplate] = useState<EmailTemplate | null>(null)
  const [subject, setSubject] = useState('')
  const [body, setBody] = useState('')

  const [loading, setLoading] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)
  const [successMsg, setSuccessMsg] = useState<string | null>(null)
  const [resetting, setResetting] = useState(false)
  const [confirmReset, setConfirmReset] = useState(false)
  const saveTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const [preview, setPreview] = useState<EmailTemplatePreview | null>(null)
  const [previewing, setPreviewing] = useState(false)
  const [previewError, setPreviewError] = useState<string | null>(null)

  const loadTemplate = useCallback(async (key: string, lang: string) => {
    setLoading(true)
    setLoadError(null)
    setSuccessMsg(null)
    setSaveError(null)
    setConfirmReset(false)
    setPreview(null)
    setPreviewing(false)
    setPreviewError(null)
    if (saveTimer.current) clearTimeout(saveTimer.current)
    try {
      const tpl = await getEmailTemplate(key, lang)
      setTemplate(tpl)
      setSubject(tpl.subject_template)
      setBody(tpl.body_template)
    } catch (err) {
      setLoadError(err instanceof ApiError ? err.message : 'Failed to load template.')
      setTemplate(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadTemplate(selectedKey, selectedLang) }, [selectedKey, selectedLang, loadTemplate])

  function clearFeedback() {
    if (successMsg) setSuccessMsg(null)
    if (saveError) setSaveError(null)
  }

  function clearPreview() {
    setPreview(null)
    setPreviewing(false)
    setPreviewError(null)
  }

  async function handlePreview() {
    setPreviewing(true)
    setPreview(null)
    setPreviewError(null)
    try {
      const result = await previewEmailTemplate(selectedKey, selectedLang, {
        subject_template: subject.trim(),
        body_template: body.trim(),
      })
      setPreview(result)
    } catch (err) {
      setPreviewError(err instanceof ApiError ? err.message : 'Preview failed.')
    } finally {
      setPreviewing(false)
    }
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault()
    if (saveTimer.current) clearTimeout(saveTimer.current)
    setSaving(true)
    setSaveError(null)
    setSuccessMsg(null)
    setConfirmReset(false)
    try {
      const updated = await saveEmailTemplate(selectedKey, selectedLang, {
        subject_template: subject.trim(),
        body_template: body.trim(),
      })
      setTemplate(updated)
      setSubject(updated.subject_template)
      setBody(updated.body_template)
      setSuccessMsg(t('adminTplSaved'))
      saveTimer.current = setTimeout(() => setSuccessMsg(null), 4000)
    } catch (err) {
      setSaveError(err instanceof ApiError ? err.message : 'Save failed.')
    } finally {
      setSaving(false)
    }
  }

  async function handleReset() {
    if (saveTimer.current) clearTimeout(saveTimer.current)
    setResetting(true)
    setSaveError(null)
    setSuccessMsg(null)
    try {
      const reset = await resetEmailTemplate(selectedKey, selectedLang)
      setTemplate(reset)
      setSubject(reset.subject_template)
      setBody(reset.body_template)
      setConfirmReset(false)
      setSuccessMsg(t('adminTplResetDone'))
      saveTimer.current = setTimeout(() => setSuccessMsg(null), 4000)
    } catch (err) {
      setSaveError(err instanceof ApiError ? err.message : 'Reset failed.')
    } finally {
      setResetting(false)
    }
  }

  const smtpUnavailable = !smtpLoading && !smtpAvailable
  const showPreviewPanel = previewing || preview !== null || previewError !== null

  return (
    <SectionCard title={t('adminTplTitle')} description={t('adminTplDesc')}>
      {smtpUnavailable && (
        <div className="mb-4 flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2.5 text-sm text-amber-700 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-400">
          <AlertTriangle size={14} className="mt-0.5 shrink-0" aria-hidden="true" />
          {t('adminTplSmtpWarning')}
        </div>
      )}

      {/* Selectors */}
      <div className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div>
          <label htmlFor="tpl-key" className={LABEL}>{t('adminTplSelectLabel')}</label>
          <select id="tpl-key" className={INPUT} value={selectedKey}
            onChange={e => { setSelectedKey(e.target.value) }} disabled={loading}>
            {TEMPLATE_KEYS.map(({ value, label }) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="tpl-lang" className={LABEL}>{t('language')}</label>
          <select id="tpl-lang" className={INPUT} value={selectedLang}
            onChange={e => { setSelectedLang(e.target.value) }} disabled={loading}>
            {LANGUAGES.map(({ value, label }) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>
        </div>
      </div>

      {loading && (
        <div className="flex items-center gap-2 py-8 text-sm text-muted-foreground">
          <Loader2 size={14} className="animate-spin" aria-hidden="true" /> {t('loading')}
        </div>
      )}

      {!loading && loadError && (
        <div className="flex items-start gap-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
          <AlertCircle size={15} className="mt-0.5 shrink-0" aria-hidden="true" />
          <div>
            <p className="font-medium">{t('adminTplLoadFailed')}</p>
            <p className="mt-0.5 text-xs">{loadError}</p>
            <Button size="sm" variant="outline" className="mt-3"
              onClick={() => loadTemplate(selectedKey, selectedLang)}>{t('retry')}</Button>
          </div>
        </div>
      )}

      {!loading && !loadError && template && (
        <div className={showPreviewPanel ? 'flex flex-col gap-4 xl:flex-row xl:items-start' : undefined}>
        <div className={showPreviewPanel ? 'min-w-0 xl:flex-1' : undefined}>
        <form onSubmit={handleSave} className="flex flex-col gap-4">
          {/* Status / custom indicator */}
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            {template.is_custom
              ? <span className="rounded-full border border-blue-200 bg-blue-50 px-2 py-0.5 text-blue-700 dark:border-blue-800 dark:bg-blue-950 dark:text-blue-400">{t('adminTplCustom')}</span>
              : <span className="rounded-full border border-border bg-muted px-2 py-0.5 text-muted-foreground">{t('adminTplDefault')}</span>
            }
            {template.updated_at && (
              <span>{t('adminTplLastUpdated')} {new Date(template.updated_at).toLocaleDateString()}</span>
            )}
          </div>

          {/* Available variables */}
          {template.available_variables.length > 0 && (
            <div className="rounded-md border border-border bg-muted/30 px-3 py-2">
              <p className="mb-1.5 text-xs font-medium text-foreground">{t('adminTplAvailVars')}</p>
              <div className="flex flex-wrap gap-1.5">
                {template.available_variables.map(v => (
                  <code key={v} className="rounded border border-border bg-background px-1.5 py-0.5 text-[11px] text-foreground">{`{${v}}`}</code>
                ))}
              </div>
            </div>
          )}

          {/* Subject */}
          <div>
            <label htmlFor="tpl-subject" className={LABEL}>{t('adminTplSubjectLabel')} <span className="text-destructive">*</span></label>
            <input id="tpl-subject" type="text" className={INPUT} value={subject}
              required onChange={e => { setSubject(e.target.value); clearFeedback() }} disabled={saving || resetting} />
          </div>

          {/* Body */}
          <div>
            <label htmlFor="tpl-body" className={LABEL}>{t('adminTplBodyLabel')} <span className="text-destructive">*</span></label>
            <textarea id="tpl-body" className={TEXTAREA} rows={12} value={body}
              required onChange={e => { setBody(e.target.value); clearFeedback() }} disabled={saving || resetting} />
          </div>

          {/* Actions */}
          <div className="flex flex-wrap items-center gap-2">
            <Button type="submit" size="sm" disabled={saving || resetting}>
              {saving && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
              {t('adminTplSaveBtn')}
            </Button>
            <Button type="button" size="sm" variant="outline" disabled={saving || resetting || previewing}
              onClick={handlePreview}>
              {previewing
                ? <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />
                : <Eye size={13} className="mr-1.5" aria-hidden="true" />}
              {t('adminTplPreviewTitle')}
            </Button>
            {!confirmReset ? (
              <Button type="button" size="sm" variant="outline" disabled={saving || resetting}
                onClick={() => setConfirmReset(true)}>
                <RotateCcw size={13} className="mr-1.5" aria-hidden="true" />
                {t('adminTplResetBtn')}
              </Button>
            ) : (
              <>
                <Button type="button" size="sm" variant="destructive" disabled={resetting}
                  onClick={handleReset}>
                  {resetting && <Loader2 size={13} className="mr-1.5 animate-spin" aria-hidden="true" />}
                  {t('adminTplConfirmReset')}
                </Button>
                <Button type="button" size="sm" variant="outline" disabled={resetting}
                  onClick={() => setConfirmReset(false)}>
                  {t('cancel')}
                </Button>
              </>
            )}
          </div>

          {saveError && (
            <div className="flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-3 py-2.5 text-sm text-red-700 dark:border-red-800 dark:bg-red-950 dark:text-red-400">
              <XCircle size={14} className="shrink-0" aria-hidden="true" />
              <span className="flex-1">{saveError}</span>
              <button type="button" onClick={() => setSaveError(null)}
                className="ml-1 shrink-0 rounded hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring" aria-label={t('dismiss')}>
                <X size={13} aria-hidden="true" />
              </button>
            </div>
          )}
          {successMsg && (
            <div className="flex items-center gap-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2.5 text-sm text-emerald-700 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-400">
              <CheckCircle2 size={14} className="shrink-0" aria-hidden="true" />
              <span className="flex-1">{successMsg}</span>
              <button type="button" onClick={() => { if (saveTimer.current) clearTimeout(saveTimer.current); setSuccessMsg(null) }}
                className="ml-1 shrink-0 rounded hover:opacity-70 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring" aria-label={t('dismiss')}>
                <X size={13} aria-hidden="true" />
              </button>
            </div>
          )}
        </form>
        </div>

        {showPreviewPanel && (
          <div className="w-full xl:w-[520px] xl:shrink-0 xl:sticky xl:top-20">
            <AdminEmailTemplatePreview
              preview={preview}
              loading={previewing}
              error={previewError}
              onDismiss={clearPreview}
            />
          </div>
        )}
        </div>
      )}
    </SectionCard>
  )
}
