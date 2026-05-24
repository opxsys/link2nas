export function hideMainApp() {
  const mainApp = document.getElementById("main-app");

  if (mainApp) {
    mainApp.hidden = true;
  }
}

export function showMainApp() {
  const authPage = document.getElementById("auth-page");
  const mainApp = document.getElementById("main-app");

  if (authPage) {
    authPage.hidden = true;
    authPage.innerHTML = "";
  }

  if (mainApp) {
    mainApp.hidden = false;
  }
}

export function escapeAuthHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}
