export function getPublicTokenFromUrl() {
  const params = new URLSearchParams(window.location.search);
  return String(params.get("token") || "").trim();
}

export function isInviteRoute() {
  return window.location.pathname === "/invite";
}

export function isPasswordResetRoute() {
  return window.location.pathname === "/reset-password";
}

export function isMagicLoginRoute() {
  return window.location.pathname === "/magic-login";
}

export function isEmailVerificationRoute() {
  return window.location.pathname === "/verify-email";
}

export function isPublicAccountRoute() {
  return (
    isInviteRoute() ||
    isPasswordResetRoute() ||
    isMagicLoginRoute() ||
    isEmailVerificationRoute()
  );
}
