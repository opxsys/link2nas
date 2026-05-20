let _themeMediaListener = null;

export function applyTheme(stored) {
  if (_themeMediaListener) {
    window.matchMedia("(prefers-color-scheme: dark)").removeEventListener("change", _themeMediaListener);
    _themeMediaListener = null;
  }
  const valid = new Set(["auto", "light", "night", "high_contrast", "colorblind"]);
  const pref = valid.has(stored) ? stored : "auto";
  let resolved = pref;
  if (pref === "auto") {
    resolved = window.matchMedia("(prefers-color-scheme: dark)").matches ? "night" : "light";
    _themeMediaListener = (e) => {
      document.documentElement.dataset.theme = e.matches ? "night" : "light";
    };
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", _themeMediaListener);
  }
  document.documentElement.dataset.theme = resolved;
}

export function applyCurrentUserTheme(user) {
  const theme = user?.ui_theme || "auto";
  applyTheme(theme);
  localStorage.setItem("link2nas_theme", theme);
}
