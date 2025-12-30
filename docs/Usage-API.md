# Link2NAS — Documentation d’utilisation (Web + API)

Cette doc décrit **l’usage réel** de l’application à partir des routes Flask effectivement exposées.

## Routes exposées (exact)

| Route | Méthodes | Type | Auth admin |
|---|---:|---|---|
| `/` | GET, POST | Page | Non |
| `/admin` | GET, POST | Page | Oui |
| `/status` | GET | Page | Oui |
| `/api/submit` | POST | API | Non |
| `/api/pending_torrents` | GET | API | Non |
| `/api/completed_torrents` | GET | API | Non |
| `/api/capabilities` | GET | API | Non |
| `/api/status` | GET | API | Oui |
| `/api/admin/submit_and_send` | POST | API | Oui |
| `/send_to_nas/<torrent_id>` | POST | Action | Oui |
| `/delete_torrent/<torrent_id>` | POST | Action | Oui |
| `/delete_all_completed` | POST | Action | Oui |
| `/debug_redis` | GET | Debug | Oui (recommandé) |

> **Auth admin** : basée sur **Basic Auth** (utilisateur/mot de passe).  
> Note : si tu as modifié les décorateurs, considère ce tableau comme la cible : **toutes les routes “action/admin/debug/status” doivent être admin-only**.

---

# 1) Pages et parcours utilisateur

## `/` — Page principale

### Ajouter un lien (direct / magnet)
Deux voies usuelles :
- **Lien direct** AllDebrid (ou compatible AllDebrid)
- **Magnet** (`magnet:?xt=...`)

Comportement attendu :
- l’item est enregistré en Redis (état centralisé)
- l’UI affiche immédiatement l’item en **Pending** (si pas de liens exploitables tout de suite)
- l’item passe en **Completed** dès que des liens fichiers sont disponibles

### Pending vs Completed
- **Pending** : l’item existe, mais **pas encore de liens fichiers** exploitables (ou en attente de récupération côté AllDebrid)
- **Completed** : l’item a **au moins 1 lien** (règle : `links_count > 0`)

### Copier les liens / supprimer
Sur un item Completed :
- copie de lien (fichier par fichier)
- copie “tous les liens”
- suppression de l’item

> La suppression supprime l’état Redis (ou marque “deleted” selon l’implémentation).

---

## Comprendre les statuts

Link2NAS suit **deux niveaux de statut** :

### `status` = état AllDebrid (technique)
Exemples typiques :
- `pending`, `ready`, `completed`, `error` (selon ce que renvoie AllDebrid)

Ce statut est utile pour :
- comprendre si AllDebrid a fini de traiter le magnet
- diagnostiquer un échec côté AllDebrid

### `app_status` = workflow interne Link2NAS (NAS)
Exemples :
- `nas_pending` : l’utilisateur/admin a demandé l’envoi NAS, en attente de traitement scheduler
- `nas_sent` : envoi vers Download Station OK
- `nas_failed` : tentative faite, erreur stockée (`nas_error`)

Ce statut répond à la question :
> “Où en est l’envoi vers le NAS ?”

---

## `/admin` — Page admin

### Auth Basic (user/pass)
- Protection par **Basic Auth**
- Valeurs configurées dans le `.env` (voir section Configuration)
- Reco : **ne jamais exposer** `/admin` sans TLS et sans reverse-proxy si Internet

### Actions admin
Selon l’UI :
- soumettre un lien/magnet et lancer l’envoi NAS (workflow complet)
- relancer un envoi NAS (“retry”) sur un item `nas_failed`
- suppression (y compris “delete all completed”)

### Ce que l’admin voit en plus
- badges NAS (`nas_pending`, `nas_sent`, `nas_failed`)
- détails d’erreur NAS (`nas_error`)
- timestamps de tentative (`nas_last_attempt`, `sent_to_nas_at`)

---

## `/status` et `/api/status` — Diagnostic/health

### À quoi ça sert
Donne un “tableau de bord santé” :
- ping AllDebrid
- test endpoints AllDebrid (user, magnet/status, magnet/files, link/unlock)
- état premium AllDebrid (cache Redis)
- ping Redis
- ping NAS (si activé)

### Activation/désactivation
Contrôlé par un flag (ex : `STATUS_ROUTE_ENABLED=1/0`).  
Si désactivé : la route renvoie 404.

### Signification de `overall`
- **green** : tout est OK (ou ce qui est activé est OK)
- **yellow** : au moins un composant est dégradé (timeouts réseau, premium non OK, Redis KO, NAS KO si activé, etc.)
- **red** : endpoints AllDebrid “discontinued” détecté (API retirée) ou cas critique équivalent

---

# 2) API (minimale, la vraie)

## Auth
- Endpoints **admin-only** : Basic Auth requis (voir routes plus haut)
- Endpoints “public” : pas d’auth (à garder derrière réseau de confiance si possible)

## `POST /api/submit` — Ajouter un item

Usage : ajouter un lien direct ou magnet.

### Exemple (curl)
```bash
curl -sS -X POST http://localhost:5000/api/submit \
  -H 'Content-Type: application/json' \
  -d '{"items":["magnet:?xt=urn:btih:...","https://alldebrid.com/f/..."]}'
```

---

## `GET /api/pending_torrents` — Liste Pending

```bash
curl -sS http://localhost:5000/api/pending_torrents | jq .
```

---

## `GET /api/completed_torrents` — Liste Completed

```bash
curl -sS http://localhost:5000/api/completed_torrents | jq .
```

---

## `POST /send_to_nas/<torrent_id>` — Déclencher envoi NAS (ou retry)

Admin-only.

```bash
curl -sS -X POST -u "ADMIN_USER:ADMIN_PASS" \
  http://localhost:5000/send_to_nas/12345 | jq .
```

---

## `POST /delete_torrent/<torrent_id>` — Supprimer un item

Admin-only.

```bash
curl -sS -X POST -u "ADMIN_USER:ADMIN_PASS" \
  http://localhost:5000/delete_torrent/12345 | jq .
```

---

## `POST /delete_all_completed` — Purge Completed

Admin-only.

```bash
curl -sS -X POST -u "ADMIN_USER:ADMIN_PASS" \
  http://localhost:5000/delete_all_completed | jq .
```

---

## `GET /api/capabilities` — Capacités serveur

```bash
curl -sS http://localhost:5000/api/capabilities | jq .
```

---

## `GET /api/status` — JSON health

Admin-only.

```bash
curl -sS -u "ADMIN_USER:ADMIN_PASS" \
  http://localhost:5000/api/status | jq .
```

---

## `POST /api/admin/submit_and_send` — Admin “tout-en-un”

Admin-only.

```bash
curl -sS -X POST -u "ADMIN_USER:ADMIN_PASS" \
  http://localhost:5000/api/admin/submit_and_send \
  -H 'Content-Type: application/json' \
  -d '{"items":["magnet:?xt=urn:btih:..."]}' | jq .
```

---

# 3) États et workflow

## Règles clés
- **Un magnet est considéré TERMINÉ dès que `links_count > 0`.**
- **Unlock JIT** : déverrouillage des URLs **juste avant** l’envoi NAS.
- **Lock Redis** : évite les doubles envois NAS concurrents.

## Séquence standard
1. Soumission
2. Pending
3. Refresh scheduler (récupération fichiers)
4. Completed (`links_count > 0`)
5. (optionnel) Demande envoi NAS (`app_status=nas_pending`)
6. Envoi Synology : `nas_sent` ou `nas_failed`

---

# 4) Configuration (.env)

> **Source de vérité** : `.env.example` du repo.  
> Ci-dessous : guide opérationnel (à aligner avec ton `.env.example`).

## Obligatoires (runtime)
- `FLASK_SECRET_KEY`
- `ALLDEBRID_APIKEY`
- `REDIS_HOST`, `REDIS_PORT` (et éventuellement `REDIS_PASSWORD`, `REDIS_DB`)
- `ADMIN_USER`, `ADMIN_PASS`

## NAS (si activé)
- `NAS_ENABLED=1`
- `SYNOLOGY_URL`
- `SYNOLOGY_USER`
- `SYNOLOGY_PASSWORD`

## Scheduler
- `SCHEDULER_ENABLED=1` (uniquement côté scheduler)
- `MAX_UNLOCK_PER_RUN` (anti rate-limit)
- `SCHEDULER_REFRESH_MAX_PER_RUN` (si présent)

## Status
- `STATUS_ROUTE_ENABLED=1`
- `STATUS_HTTP_TIMEOUT`
- `STATUS_DSM_TIMEOUT`
- `AD_PING_PATH`

---

# 6) Sécurité et limites

## Sécurité
- Basic Auth ≠ IAM complet : mets ça derrière TLS + reverse-proxy si exposé.
- Reco : filtrage IP / VPN.

## Limites
- Pas de multi-user
- Pas de quotas / permissions fines
- Dépendance AllDebrid (disponibilité, rate-limit)

---

# Annexe — lister les routes réellement exposées

```bash
set -a; source .env; set +a
python - <<'EOF'
from link2nas.config import Settings
from link2nas.webapp import create_app
s = Settings.from_env()
app = create_app(s)
for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
    methods = ",".join(sorted(m for m in rule.methods if m not in {"HEAD","OPTIONS"}))
    print(f"{rule.rule:30} [{methods}] -> {rule.endpoint}")
EOF
```
