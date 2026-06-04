import { useSyncExternalStore } from 'react'

export type LangCode = 'en' | 'fr'

const STORAGE_KEY = 'link2nas-lang'
const listeners = new Set<() => void>()

function getStoredLang(): LangCode {
  try {
    const v = localStorage.getItem(STORAGE_KEY)
    if (v === 'en' || v === 'fr') return v as LangCode
  } catch { /* ignore */ }
  return 'fr'
}

let _lang: LangCode = getStoredLang()

function notify(): void {
  listeners.forEach(cb => cb())
}

export function setAuthLang(l: LangCode): void {
  _lang = l
  try { localStorage.setItem(STORAGE_KEY, l) } catch { /* ignore */ }
  notify()
}

type Strings = Record<string, string>

const EN: Strings = {
  appTaglineFallback: 'Manage your download jobs',
  loginTitle: 'Sign in',
  loginSubtitle: 'Sign in to your account',
  setupTitle: 'Initial Setup',
  setupSubtitle: 'Create the first administrator account',
  email: 'Email',
  password: 'Password',
  displayName: 'Display name (optional)',
  confirmPassword: 'Confirm password',
  signIn: 'Sign in',
  createAdmin: 'Create administrator',
  creatingAdmin: 'Creating…',
  forgotPassword: 'Forgot password?',
  magicLogin: 'Receive a login link by email',
  back: 'Back',
  backToLogin: 'Back to sign in',
  sendResetLink: 'Send reset link',
  sendLoginLink: 'Send login link',
  sentTitle: 'Email sent',
  resetEmailSent: 'If an account matches this address, a reset link will be sent.',
  magicEmailSent: 'If an account matches this address, a login link will be sent.',
  smtpUnavailable: 'Unavailable: email sending is not configured.',
  passwordMismatch: 'Passwords do not match.',
  appearance: 'Appearance',
  language: 'Language',
  confirmingLogin: 'Signing in…',
  loginSuccess: 'Login successful, redirecting…',
  invalidToken: 'This link is invalid or has expired.',
  newPassword: 'New password',
  confirmNewPassword: 'Confirm new password',
  resetPassword: 'Reset password',
  resettingPassword: 'Resetting…',
  passwordResetSuccess: 'Password reset successfully.',
  goToLogin: 'Go to sign in',
}

const FR: Strings = {
  appTaglineFallback: 'Piloter vos jobs de débridage',
  loginTitle: 'Connexion',
  loginSubtitle: 'Connectez-vous à votre compte',
  setupTitle: 'Installation initiale',
  setupSubtitle: 'Créer le premier compte administrateur',
  email: 'Email',
  password: 'Mot de passe',
  displayName: 'Nom affiché (optionnel)',
  confirmPassword: 'Confirmer le mot de passe',
  signIn: 'Se connecter',
  createAdmin: "Créer l'administrateur",
  creatingAdmin: 'Création en cours…',
  forgotPassword: 'Mot de passe oublié ?',
  magicLogin: 'Recevoir un lien de connexion par email',
  back: 'Retour',
  backToLogin: 'Retour à la connexion',
  sendResetLink: 'Envoyer le lien de réinitialisation',
  sendLoginLink: 'Envoyer le lien de connexion',
  sentTitle: 'Email envoyé',
  resetEmailSent: "Si un compte correspond à cette adresse, un lien de réinitialisation sera envoyé.",
  magicEmailSent: "Si un compte correspond à cette adresse, un lien de connexion sera envoyé.",
  smtpUnavailable: "Indisponible : l'envoi d'emails n'est pas configuré.",
  passwordMismatch: 'Les mots de passe ne correspondent pas.',
  appearance: 'Apparence',
  language: 'Langue',
  confirmingLogin: 'Connexion en cours…',
  loginSuccess: 'Connexion réussie, redirection…',
  invalidToken: 'Ce lien est invalide ou a expiré.',
  newPassword: 'Nouveau mot de passe',
  confirmNewPassword: 'Confirmer le nouveau mot de passe',
  resetPassword: 'Réinitialiser le mot de passe',
  resettingPassword: 'Réinitialisation…',
  passwordResetSuccess: 'Mot de passe réinitialisé avec succès.',
  goToLogin: 'Aller à la connexion',
}

export function useAuthLang(): {
  lang: LangCode
  setLang: (l: LangCode) => void
  t: (key: string) => string
} {
  const lang = useSyncExternalStore(
    cb => { listeners.add(cb); return () => listeners.delete(cb) },
    () => _lang,
    () => _lang,
  )
  const t = (key: string): string => {
    const strings = lang === 'en' ? EN : FR
    return strings[key] ?? key
  }
  return { lang, setLang: setAuthLang, t }
}
