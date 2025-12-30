// options.js
// Test serveur fiable :
// - utilise la valeur saisie (même si non enregistrée)
// - fallback storage si champ vide
// - affiche reach/nas/version + détail
// - met à jour les badges (health + capabilities) sans casser le DOM

const $ = (id) => document.getElementById(id);
const CAPABILITIES_ENDPOINT = "/api/capabilities";

function normBaseUrl(u) {
  return String(u || "").trim().replace(/\/+$/, "");
}

// ---------- UI helpers (compatibles avec ton options.html) ----------

function setStatus(text, kind = "muted") {
  const el = $("status"); // class .statusline dans HTML
  el.textContent = text || "";
  el.className = `statusline ${kind}`; // IMPORTANT: statusline (pas status)
}

function setDot(dotId, kind) {
  const el = $(dotId);
  if (!el) return;
  el.className = `dot ${kind || ""}`.trim();
}

function setHealthBadge(kind, text) {
  setDot("healthDot", kind);
  const t = $("healthText");
  if (t) t.textContent = text || "—";
}

function setCapsPill(kind, text) {
  // IMPORTANT: ne pas écraser capsPill.textContent (sinon tu détruis ses enfants)
  setDot("capsDot", kind);
  const s = $("capsSummary");
  if (s) s.textContent = text || "—";
}

function setKv(id, v) {
  const el = $(id);
  if (!el) return;
  el.textContent = (v === undefined || v === null || v === "") ? "—" : String(v);
}

function boolText(v) {
  return v ? "Oui" : "Non";
}

function showAdminWarn(show, text = "") {
  const el = $("adminWarn");
  if (!el) return;
  el.textContent = text || "";
  el.className = show ? "warnbox show" : "warnbox";
}

// ---------- storage ----------

async function load() {
  const cfg = await chrome.storage.sync.get({
    baseUrl: "http://192.168.100.1:5000",
    adminUser: "admin",
    adminPass: "",
    openAfterSubmit: true
  });

  $("serverBaseUrl").value = cfg.baseUrl || "";
  $("adminUser").value = cfg.adminUser || "";
  $("adminPass").value = cfg.adminPass || "";
  $("openAfterSubmit").checked = !!cfg.openAfterSubmit;

  // état initial
  setStatus("", "muted");
  setHealthBadge("", "Non testé");
  setCapsPill("", "non testé");

  setKv("kvBase", "—");
  setKv("kvReach", "—");
  setKv("kvNas", "—");
  setKv("kvVersion", "—");
  setKv("kvDetail", "—");
  showAdminWarn(false);
}

async function save() {
  const baseUrl = normBaseUrl($("serverBaseUrl").value);
  const adminUser = ($("adminUser").value || "").trim() || "admin";
  const adminPass = $("adminPass").value || "";
  const openAfterSubmit = !!$("openAfterSubmit").checked;

  if (!baseUrl) {
    setStatus("URL serveur manquante.", "err");
    return;
  }

  await chrome.storage.sync.set({ baseUrl, adminUser, adminPass, openAfterSubmit });
  setStatus("Enregistré.", "ok");
}

// ---------- HTTP ----------

async function fetchJson(url, { method = "GET", timeoutMs = 4500, headers = {} } = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);

  try {
    const res = await fetch(url, { method, headers, signal: ctrl.signal });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    return { ok: res.ok, status: res.status, json, text };
  } finally {
    clearTimeout(t);
  }
}

// ---------- Test serveur ----------

async function testServer() {
  // 1) base = champ (même si pas enregistré)
  let base = normBaseUrl($("serverBaseUrl").value);

  // 2) fallback storage si champ vide
  const cfg = await chrome.storage.sync.get({
    baseUrl: "",
    adminPass: ""
  });

  if (!base) base = normBaseUrl(cfg.baseUrl);

  if (!base) {
    setHealthBadge("err", "Serveur KO");
    setCapsPill("err", "KO");
    setStatus("URL serveur manquante.", "err");
    return;
  }

  // reset UI
  setStatus("Test en cours…", "warn");
  setHealthBadge("warn", "Test en cours");
  setCapsPill("warn", "test…");
  showAdminWarn(false);

  setKv("kvBase", base);
  setKv("kvReach", "—");
  setKv("kvNas", "—");
  setKv("kvVersion", "—");
  setKv("kvDetail", "—");

  const url = `${base}${CAPABILITIES_ENDPOINT}`;

  let r;
  try {
    r = await fetchJson(url, { method: "GET", timeoutMs: 4500 });
  } catch (e) {
    setHealthBadge("err", "Serveur KO");
    setCapsPill("err", "KO (network)");
    setKv("kvReach", "KO (network)");
    setKv("kvDetail", String(e?.message || e));
    setStatus("Serveur injoignable (network).", "err");
    return;
  }

  if (!r.ok || !r.json || r.json.success !== true) {
    setHealthBadge("err", "Serveur KO");
    setCapsPill("err", `KO (HTTP ${r.status})`);
    setKv("kvReach", `KO (HTTP ${r.status})`);
    setKv("kvDetail", r.json ? JSON.stringify(r.json) : (r.text || "").slice(0, 300));
    setStatus(`Échec: /api/capabilities (HTTP ${r.status})`, "err");
    return;
  }

  const caps = r.json.capabilities || {};
  const nasEnabled = !!caps.nas_enabled;
  const version = (r.json.version && String(r.json.version).trim()) ? String(r.json.version).trim() : "";

  setKv("kvReach", "OK");
  setKv("kvNas", boolText(nasEnabled));
  setKv("kvVersion", version || "—");
  setKv("kvDetail", JSON.stringify(caps));

  if (nasEnabled && !String(cfg.adminPass || "")) {
    showAdminWarn(true, "NAS activé côté serveur : configure aussi le mot de passe admin pour utiliser “Envoyer au NAS”.");
  }

  setHealthBadge("ok", "Serveur OK");
  setCapsPill("ok", nasEnabled ? "OK (NAS ON)" : "OK (NAS OFF)");
  setStatus(nasEnabled ? "OK — NAS activé" : "OK — NAS désactivé", "ok");

  try {
    await chrome.runtime.sendMessage({ type: "REFRESH_MENUS", baseUrl: base });
  } catch (_) {
    // pas bloquant : si ça échoue, le test serveur reste valide
  }
}

// ---------- wiring ----------

document.addEventListener("DOMContentLoaded", async () => {
  await load();

  const btnSave = $("save");
  const btnTest = $("testServer"); // <= match options.html

  if (btnSave) btnSave.addEventListener("click", save);
  if (btnTest) btnTest.addEventListener("click", testServer);
});
