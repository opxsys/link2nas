# Changelog

All notable changes to this project will be documented in this file.

Format: Keep a Changelog  
The project does not strictly follow SemVer (version is informational).

## [1.3.2] - 2026-01-02
### Added
- `link2nas/nas_send.py`: pipeline NAS robuste (Redis item -> DSM DownloadStation) :
  - lecture `magnet:*` / `direct:*`, parsing links via `parse_links_dicts()`
  - unlock AllDebrid (`alldebrid.com/f/...` -> `debrid.it/dl/...`)
  - mode dossier (multi-liens/batch) avec création FileStation + persistance `nas_folder`
  - fallback destination DownloadStation (modes `rel` / `fs` / `folder`) + persistance `ds_dest_mode`
  - logs "safe" (URLs redacted host#hash), anti-doublons si création partielle de tâches
- `link2nas/synology_fs.py`: helpers DSM WebAPI centralisés (Auth / FileStation / DownloadStation) :
  - wrapper HTTP + parsing JSON robuste (DSM renvoie souvent HTTP 200 même en erreur)
  - `SynologyApiError` "safe" (api/code/http_status + payload minimal)
  - support GET/POST via env (`DSM_AUTH_METHOD`, `DSM_FS_METHOD`, `DSM_DS_METHOD`)
  - support SynoToken via env (`DSM_ENABLE_SYNO_TOKEN`, `DSM_REQUIRE_SYNO_TOKEN`)
  - génération candidates `destination` DownloadStation (relatif, pseudo-absolu, folder-only, cas `/volumeX/...`)
- Split du web :
  - `webapp.py` limité à app Flask + routes + context UI
  - `web_helpers.py`: sanitize/redact/scrub/payload/mk_*
  - `web_auth.py`: decorator admin basé Settings (pas de global config)
  - `web_process.py`: `process_one_item_*` + send direct + locks/status redis
  - `status_checks.py`: probes AllDebrid/Redis/DSM et snapshot unique

### Changed
- AllDebrid (`link2nas/alldebrid.py`) :
  - gros refactor client : centralisation HTTP `_ad_request`, parsing JSON robuste, headers unifiés
  - logs safe (redaction URL par hash) pour debug sans fuite
  - ajout logique "redirectors" :
    - cache Redis des redirectors (hosts) + matching URL
    - endpoint expand (link/redirector) avec policy (rapidgator bypass, 1fichier expand seulement sur `/dir/`)
    - `generate_links_safe()` normalise `URL -> N liens directs`
  - harmonisation/clarification des erreurs (retours structurés), `unlock_link_safe` conservé mais réimplémenté via wrapper
- `.env.example` :
  - réorganisation par blocs (Core/Admin/Redis/Scheduler/AllDebrid/NAS-Synology/UI premium)
  - nouvelles variables (logging/status/scheduler/AD redirectors/Synology)
  - renommages/clarifications (ex: `ADMIN_UI_ENABLED`, `ADMIN_REALM` sans guillemets)
  - ajout `APP_VERSION`, placeholder `FLASK_SECRET_KEY` plus clair
  - ajout newline final
- Synology legacy (`link2nas/synology.py`) :
  - `verify_ssl` via `SYNOLOGY_VERIFY_SSL`, normalisation URL, import os
  - fix majeur : `synology_ping_safe()` prend `Settings` (plus de `os.getenv()`/globals) + checks config + verify SSL
  - `send_to_download_station()` marqué legacy/simple + verify SSL + URL robust
- Logging (`link2nas/logging_setup.py`) :
  - LOG_LEVEL piloté par env (support `LOG_LEVEL` et `LOGLEVEL`)
  - ajout `LOG_FORCE` (force reset handlers) + stream stdout + format amélioré
  - setLevel cohérent du logger projet `link2nas.*`
- Redis store (`link2nas/redis_store.py`) :
  - état NAS persistant par item :
    - nouvelles clés `nas_folder`, `ds_dest_mode`
  - support "direct batch" via `store_direct_batch()` (N liens dans `direct:{id}` + `is_batch=1`)
  - enrichissement metadata (`source_url`, `source_domain`, `is_batch`) + alignement items direct/magnet
  - helpers dédiés `get_nas_folder()` / `set_nas_folder()`
- Scheduler jobs (`link2nas/scheduler_jobs.py`) :
  - NAS : suppression de l’unlock JIT local + remplacement par `send_item_to_nas_safe(s, rdb, key)`
  - refresh magnets plus robuste (decode bytes/str, best-effort, évite d’écraser un état déjà complet)
  - logs NAS simplifiés (détail dans `nas_send.py`)
  - fix config : `scheduler_refresh_max_per_run` -> `max_unlock_per_run` (align env)
- Scheduler runner (`scheduler_runner.py`) :
  - logging centralisé via `setup_logging()`
  - suppression `dotenv.load_dotenv()` (runner ne charge plus `.env` tout seul)
- Template UI (`templates/index.html`) :
  - grille fichiers rework (breakpoints + min width) pour éviter cartes trop étroites
  - rendu "single-file" (1 seul fichier => ligne directe au lieu d’un `<details>`)
  - correctif anti-débordement filenames (clamp 2 lignes + overflow-wrap:anywhere)
  - refresh JS (`refreshCompletedOnce`) aligné sur la même logique single-file vs grid

### Fixed
- `synology_ping_safe()` : correction ImportError / attente status (signature et imports cohérents)
- Réduction des fuites : construction `all_completed_links` uniquement côté admin + `/debug_redis` protégé + scrub
- Suppression `logging.basicConfig()` local webapp (évite doublons handlers)





## [1.3.0] - 2025-12-30

### Added
- Modular architecture (web service + scheduler service)
- APScheduler-based background processing
- Chrome extension support
- Status page and health endpoints
- Centralized configuration via environment variables

### Changed
- Secure configuration handling (no secrets in logs or repr)
- Systemd services split (web / scheduler)

### Security
- Secrets fully externalized to `.env`
- Safe `Settings.__repr__` implementation
