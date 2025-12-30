// service_worker.js (Manifest V3)
// Menus PUBLIC toujours présents.
// Menus NAS/ADMIN seulement si nas_enabled=true (via /api/capabilities).

const MENU_PUBLIC_LINK = "alld_public_link";
const MENU_ADMIN_LINK  = "alld_admin_link";
const MENU_PUBLIC_SEL  = "alld_public_selection";
const MENU_ADMIN_SEL   = "alld_admin_selection";

const ADMIN_GUI = "/admin";
const ADMIN_ENDPOINT = "/api/admin/submit_and_send";
const PUBLIC_ENDPOINT = "/api/submit";
const CAPABILITIES_ENDPOINT = "/api/capabilities";

// cache capabilities (par baseUrl) en mémoire SW
const capsCache = new Map(); // base -> { ts, data }

// ---------------- utils parsing ----------------

function isSupportedLink(url) {
  if (!url) return false;
  const u = String(url).trim();
  return u.startsWith("magnet:?") || u.startsWith("http://") || u.startsWith("https://");
}

function extractLinksFromText(text) {
  const s = String(text || "");
  const out = [];

  const magnetRe = /(magnet:\?[^\s"'<>]+)/ig;
  for (const m of s.matchAll(magnetRe)) out.push(m[1]);

  const httpRe = /(https?:\/\/[^\s"'<>]+)/ig;
  for (const m of s.matchAll(httpRe)) out.push(m[1]);

  return Array.from(new Set(out)).filter(isSupportedLink);
}

async function getSettings() {
  return await chrome.storage.sync.get({
    baseUrl: "http://192.168.100.1:5000",
    adminUser: "admin",
    adminPass: "",
    openAfterSubmit: true
  });
}

function basicAuthHeader(user, pass) {
  const token = btoa(`${user}:${pass}`);
  return `Basic ${token}`;
}

// ---------------- UI feedback ----------------

async function setBadge(ok) {
  try {
    await chrome.action.setBadgeText({ text: ok ? "✓" : "!" });
    await chrome.action.setBadgeBackgroundColor({ color: ok ? "#137333" : "#b3261e" });
    setTimeout(() => chrome.action.setBadgeText({ text: "" }).catch(() => {}), 2000);
  } catch (_) {}
}

async function notify(title, linesOrMessage, context = "") {
  const message = Array.isArray(linesOrMessage)
    ? linesOrMessage.join("\n").slice(0, 320)
    : String(linesOrMessage || "").slice(0, 320);

  try {
    await chrome.notifications.create({
      type: "basic",
      iconUrl: "icon48.png",
      title,
      message,
      contextMessage: context
    });
  } catch (e) {
    try {
      await chrome.notifications.create({
        type: "basic",
        iconUrl:
          "data:image/png;base64," +
          "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4////fwAJ+wP+7Zc5WQAAAABJRU5ErkJggg==",
        title,
        message,
        contextMessage: context
      });
    } catch (_) {}
  }
}

function humanizeItemError(err) {
  const code = String(err?.code || "UNKNOWN");
  const msg  = String(err?.message || "");

  if (code === "LINK_HOST_NOT_SUPPORTED") return "host non supporté";
  if (code === "LINK_DOWN") return "lien down";
  if (code === "LINK_HOST_UNAVAILABLE") return "host indisponible";
  if (code === "AUTH_REQUIRED" || code === "UNAUTHORIZED") return "auth requise";
  if (code === "NAS_DISABLED") return "NAS désactivé côté serveur";
  return `${code}${msg ? " - " + msg : ""}`;
}

// ---------------- HTTP helpers ----------------

async function fetchJsonWithTimeout(url, opts = {}, timeoutMs = 4000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);

  try {
    const res = await fetch(url, { ...opts, signal: ctrl.signal });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    return { ok: res.ok, status: res.status, json, text };
  } finally {
    clearTimeout(t);
  }
}

async function postJson(url, payload, headers = {}) {
  let res;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: JSON.stringify(payload)
    });
  } catch (e) {
    const err = new Error("Erreur réseau (serveur injoignable).");
    err.kind = "network";
    throw err;
  }

  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch {}

  if (!res.ok) {
    if (res.status === 404) {
      const err = new Error(`404: route introuvable (URL appelée: ${url})`);
      err.kind = "http";
      err.status = 404;
      err.body = json || text;
      throw err;
    }

    const err = new Error(
      (json && (json.message || json.error?.message || json.error)) || `HTTP ${res.status}`
    );
    err.kind = "http";
    err.status = res.status;
    err.body = json || text;
    throw err;
  }

  return json || {};
}

// ---------------- capabilities ----------------

async function getCapabilities(base, { cacheTtlMs = 15000 } = {}) {
  const now = Date.now();
  const cached = capsCache.get(base);
  if (cached && (now - cached.ts) < cacheTtlMs) return cached.data;

  const url = `${base}${CAPABILITIES_ENDPOINT}`;

  let r;
  try {
    r = await fetchJsonWithTimeout(url, { method: "GET" }, 4000);
  } catch (e) {
    const data = { ok: false, error: "network", nas_enabled: false, version: null, capabilities: {} };
    capsCache.set(base, { ts: now, data });
    return data;
  }

  if (!r.ok || !r.json || r.json.success !== true) {
    const data = { ok: false, error: `http_${r.status}`, nas_enabled: false, version: null, capabilities: {} };
    capsCache.set(base, { ts: now, data });
    return data;
  }

  const caps = r.json.capabilities || {};
  const data = {
    ok: true,
    version: r.json.version || null,
    capabilities: caps,
    nas_enabled: !!caps.nas_enabled
  };

  capsCache.set(base, { ts: now, data });
  return data;
}

// ---------------- context menus (rebuild) ----------------

function createMenu(def) {
  return new Promise((resolve) => {
    try {
      chrome.contextMenus.create(def, () => resolve());
    } catch (_) {
      resolve();
    }
  });
}

function removeAllMenus() {
  return new Promise((resolve) => {
    try {
      chrome.contextMenus.removeAll(() => resolve());
    } catch (_) {
      resolve();
    }
  });
}

async function ensureMenus(base) {
  // Important: rebuild complet = fiable (Chrome cache parfois update)
  await removeAllMenus();

  const caps = await getCapabilities(base);
  const nasEnabled = !!caps?.nas_enabled;

  // PUBLIC: toujours
  await createMenu({
    id: MENU_PUBLIC_LINK,
    title: "AllDebrid: Générer les liens (app)",
    contexts: ["link"]
  });
  await createMenu({
    id: MENU_PUBLIC_SEL,
    title: "AllDebrid: Générer (depuis sélection)",
    contexts: ["selection"]
  });

  // NAS/ADMIN: seulement si NAS ON
  if (nasEnabled) {
    await createMenu({
      id: MENU_ADMIN_LINK,
      title: "AllDebrid: Envoyer au NAS (admin)",
      contexts: ["link"]
    });
    await createMenu({
      id: MENU_ADMIN_SEL,
      title: "AllDebrid: NAS (depuis sélection)",
      contexts: ["selection"]
    });
  }

  console.log("[SW] ensureMenus done. NAS =", nasEnabled);
}

async function syncMenusFromSettings() {
  const s = await getSettings();
  const base = String(s.baseUrl || "").trim().replace(/\/+$/, "");
  if (!base) return;
  await ensureMenus(base);
}

// ---------------- results summarize ----------------

function summarizeBackendResult(result) {
  const created = Array.isArray(result?.created) ? result.created : [];
  const errors  = Array.isArray(result?.errors) ? result.errors : [];

  const okN = created.length;
  const koN = errors.length;

  if (okN > 0 && koN === 0) return { ok: true, msg: `OK (${okN})`, details: [] };

  if (okN === 0 && koN > 0) {
    const first = errors[0];
    return {
      ok: false,
      msg: `Échec (${koN}) : ${humanizeItemError(first?.error)}`,
      details: errors.slice(0, 4).map(e => `- ${humanizeItemError(e?.error)} (${String(e?.item||"")})`)
    };
  }

  if (okN > 0 && koN > 0) {
    const first = errors[0];
    return {
      ok: false,
      msg: `Partiel: OK ${okN}, erreurs ${koN} (ex: ${humanizeItemError(first?.error)})`,
      details: errors.slice(0, 4).map(e => `- ${humanizeItemError(e?.error)} (${String(e?.item||"")})`)
    };
  }

  return { ok: false, msg: "Aucun lien traité.", details: [] };
}

// ---------------- selection + open tab helpers ----------------

async function getSelectionTextFromTab(tabId) {
  try {
    const resp = await chrome.tabs.sendMessage(tabId, { type: "GET_SELECTION" });
    return String(resp?.text || "");
  } catch {
    return "";
  }
}

async function openOrRefreshApp(url, key) {
  const target = url.replace(/\/+$/, "");
  const st = await chrome.storage.session.get({ [key]: null });
  const tabId = st[key];

  if (tabId) {
    try {
      await chrome.tabs.update(tabId, { active: true });
      await chrome.tabs.reload(tabId);
      return;
    } catch {
      await chrome.storage.session.remove(key);
    }
  }

  const t = await chrome.tabs.create({ url: target });
  await chrome.storage.session.set({ [key]: t.id });
}

// ---------------- extension lifecycle ----------------

chrome.runtime.onInstalled.addListener(() => {
  syncMenusFromSettings().catch(() => {});
});

chrome.runtime.onStartup?.addListener(() => {
  syncMenusFromSettings().catch(() => {});
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "sync") return;
  if (changes.baseUrl || changes.adminUser || changes.adminPass || changes.openAfterSubmit) {
    capsCache.clear();
    syncMenusFromSettings().catch(() => {});
  }
});

// ---------------- click handler ----------------

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const s = await getSettings();
  const base = String(s.baseUrl || "").trim().replace(/\/+$/, "");

  if (!base) {
    await setBadge(false);
    await notify("AllDebrid - erreur", "baseUrl vide. Configure l'URL dans Options.");
    return;
  }

  try {
    let items = [];

    // link
    if (info.menuItemId === MENU_PUBLIC_LINK || info.menuItemId === MENU_ADMIN_LINK) {
      const link = info.linkUrl || "";
      if (!isSupportedLink(link)) {
        await setBadge(false);
        await notify("AllDebrid", "Lien non supporté (magnet ou http/https uniquement).");
        return;
      }
      items = [link];
    }

    // selection
    if (info.menuItemId === MENU_PUBLIC_SEL || info.menuItemId === MENU_ADMIN_SEL) {
      const tabId = tab?.id;
      const txt = tabId ? await getSelectionTextFromTab(tabId) : (info.selectionText || "");
      items = extractLinksFromText(txt);

      if (!items.length) {
        await setBadge(false);
        await notify("AllDebrid", "Aucun lien détecté dans la sélection.");
        return;
      }
    }

    // PUBLIC
    if (info.menuItemId === MENU_PUBLIC_LINK || info.menuItemId === MENU_PUBLIC_SEL) {
      const result = await postJson(`${base}${PUBLIC_ENDPOINT}`, { items });

      const sum = summarizeBackendResult(result);
      await setBadge(sum.ok);

      const msgLines = [`App: ${sum.msg}`];
      if (sum.details?.length) msgLines.push(...sum.details);

      await notify("AllDebrid", msgLines, `URL: ${base}`);

      if (s.openAfterSubmit) {
        await openOrRefreshApp(`${base}/`, "appTabId");
      }
      return;
    }

    // ADMIN/NAS
    if (info.menuItemId === MENU_ADMIN_LINK || info.menuItemId === MENU_ADMIN_SEL) {
      // Normalement ces menus n'existent pas si NAS OFF.
      // Mais si état a changé entre-temps, on recheck.
      capsCache.delete(base);
      const caps = await getCapabilities(base, { cacheTtlMs: 0 });

      if (!caps?.ok) {
        await setBadge(false);
        await notify("AllDebrid - erreur", "Impossible de lire /api/capabilities (serveur KO ?).", `URL: ${base}`);
        await ensureMenus(base);
        return;
      }

      if (!caps.nas_enabled) {
        await setBadge(false);
        await notify("AllDebrid", "NAS désactivé côté serveur (NAS_ENABLED=0).", `URL: ${base}`);
        await ensureMenus(base);
        return;
      }

      if (!s.adminPass) {
        await setBadge(false);
        await notify("AllDebrid - erreur", "Mot de passe admin non configuré (Options).", `URL: ${base}`);
        return;
      }

      const result = await postJson(
        `${base}${ADMIN_ENDPOINT}`,
        { items },
        { "Authorization": basicAuthHeader(s.adminUser, s.adminPass) }
      );

      const sum = summarizeBackendResult(result);
      await setBadge(sum.ok);

      const msgLines = [`NAS: ${sum.msg}`];
      if (sum.details?.length) msgLines.push(...sum.details);

      await notify("AllDebrid", msgLines, `URL: ${base}`);

      if (s.openAfterSubmit) {
        await openOrRefreshApp(`${base}${ADMIN_GUI}`, "adminTabId");
      }
      return;
    }

    await setBadge(false);
    await notify("AllDebrid - erreur", "Menu inconnu (extension pas à jour ?).", `URL: ${base}`);

  } catch (e) {
    console.error("[SW] handler error:", e);

    const msg =
      (e?.kind === "http")
        ? [
            `HTTP ${e.status}`,
            typeof e.body === "string" ? e.body.slice(0, 160) : ""
          ].filter(Boolean)
        : [String(e?.message || e)];

    await setBadge(false);
    await notify("AllDebrid - erreur", msg, "Vérifie l'URL.");
  }
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  const st = await chrome.storage.session.get({ appTabId: null, adminTabId: null });
  const del = {};
  if (st.appTabId === tabId) del.appTabId = null;
  if (st.adminTabId === tabId) del.adminTabId = null;
  if (Object.keys(del).length) await chrome.storage.session.set(del);
});

// ---------------- message from Options: refresh menus now ----------------

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (msg?.type === "REFRESH_MENUS") {
        const base = String(msg.baseUrl || "").trim().replace(/\/+$/, "");
        if (!base) {
          sendResponse({ ok: false, error: "baseUrl missing" });
          return;
        }

        capsCache.delete(base);
        await ensureMenus(base);
        sendResponse({ ok: true });
        return;
      }

      sendResponse({ ok: false, error: "unknown message" });
    } catch (e) {
      sendResponse({ ok: false, error: String(e?.message || e) });
    }
  })();

  return true; // async
});
