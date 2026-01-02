# TODO.md
# TODO (priorisé, actionnable)

## P0 — À faire avant de push si tu veux éviter une connerie en prod
1) `link2nas/auth.py` : corriger le `\ No newline at end of file`
- Ajouter une fin de ligne. Point.

2) Logs / privacy : chasse aux `payload={js}` dans des exceptions
- Partout où tu fais `RuntimeError(f"... payload={js}")` → remplacer par un payload “safe” (success + error.code + hint).
- Objectif : jamais d’URL / token dans logs, même en erreur.

3) `nas_send.py` — anti-doublon en fallback destination
- Aujourd’hui tu mets `stop_fallback` dans l’erreur mais tu ne l’appliques pas.
- Règle : si `partial_created > 0` => STOP immédiat, même si le code DSM est 403 (sinon doublons).

4) `nas_send.py` — mkdir idempotent
- Si le dossier existe déjà, FileStation peut renvoyer une erreur.
- Traiter “already exists” comme OK (ou faire un check préalable si dispo).
- Sinon : retries NAS = casse-gueule.

5) `scheduler_runner.py` — sans dotenv, documenter/échouer proprement
- Si tu assumes systemd: documenter `EnvironmentFile=` obligatoire.
- Sinon : au boot, détecter settings critiques manquants et `exit(1)` avec message clair.

## P1 — Robustesse (ça évite les tickets de debug)
6) AllDebrid `_ad_request` : UA + retries légers
- Ajouter un User-Agent explicite.
- Ajouter 1–2 retries sur timeout / 502 / 503 avec backoff court.

7) Redirectors : matching domain propre
- Remplacer `if d in low` par un match sur `netloc` :
  - `netloc == d` ou `netloc.endswith("." + d)`
- Réduit les faux positifs (querystring).

8) Cache redirectors : “stale-if-error”
- Si refresh échoue, conserver l’ancien cache Redis au lieu de retourner `[]`.

9) `synology.py` legacy : cohérence session/version Auth
- `synology_ping_safe` utilise `session=DownloadStation` et `version=3` en dur.
- Aligner avec `DSM_SESSION_NAME` + `DSM_AUTH_VERSION` (env) ou Settings.

10) `synology_fs.py` : erreurs explicites si modules manquants
- Si `api_info` ne contient pas `SYNO.DownloadStation.Task` ou `SYNO.FileStation...` :
  - lever `SynologyApiError(API_MISSING, ...)` au lieu d’un fallback silencieux.

11) `nas_send.py` : réutiliser la logique decode Redis existante
- Tu as déjà des helpers bytes/str côté `redis_store.py`.
- Réutiliser pour éviter divergences.

## P2 — Qualité / maintenance
12) Unifier schéma “link items”
- `generate_links_safe()` renvoie `filename/filesize`, ailleurs c’est `name/link/size`.
- Décider un schéma unique (`name`, `link`, `size`) et mapper au bon endroit.

13) Web processing : standardiser signatures de retour
- Aujourd’hui : tuples incohérents selon branches.
- Fix : toujours `(created: dict|None, err: dict|None, http_status: int|None)`.

14) Batch naming lisible
- Actuellement `redirector` ou `"batch"`.
- Mettre `slug(domain)-YYYYmmdd-HHMMSS` (tu as déjà la logique dans `nas_send`).

15) `/send_to_nas/<id>` : éviter le scan de toutes les clés
- Ajouter un index Redis `id -> redis_key` au moment du store.
- Lookup O(1).

16) Admin UI ne doit pas dépendre de NAS enabled
- Autoriser accès admin même si NAS off, mais désactiver/griser boutons "send".

17) Logging body (WEB_LOG_BODY)
- Garder OFF par défaut.
- Forcer “body log” uniquement en debug/dev (sinon tu finiras par leak).

## P3 — UI / DX (améliore sans casser)
18) Template : factoriser la double logique Jinja + JS
- Jinja: macro `files_panel(...)`
- JS: `renderFilesPanel(files)` + helpers, sinon tu vas souffrir à chaque change UI.

19) Grid CSS : `auto-fit`
- `grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));`
- Plus simple, plus robuste.

20) Confidentialité UI
- Le tooltip `title="${url}\n${size}"` expose l’URL en hover.
- Remplacer par `fname — size` ou “domain only”.

## Tests minimaux (ça paye vite)
21) Auth decorator
- OPTIONS 204
- admin off => 404
- config invalide => 401 + WWW-Authenticate realm
- mauvais creds => 401
- bons creds => 200

22) NAS pipeline (`nas_send.py`)
- NAS disabled
- redis key missing
- links_count=0
- single link => pas de dossier
- multi links => mkdir + enqueue
- mkdir exists
- destination 403 => fallback
- erreur après 1 create => pas de fallback
- persistance `nas_folder` + `ds_dest_mode`

23) DSM smoke script (outil)
- `tools/dsm_smoke.py`: API.Info -> login -> mkdir -> create task -> logout
- Affiche uniquement success / error.code (pas d’URI).
