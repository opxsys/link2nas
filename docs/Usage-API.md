# Link2NAS — Documentation d’utilisation (Web + API)
Version : 1.3.2

Cette documentation décrit le comportement réel de Link2NAS tel qu’implémenté en v1.3.2, basé sur les routes Flask effectivement exposées et sur le pipeline NAS/DSM refactoré.

---

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
| `/debug_redis` | GET | Debug | Oui |

---

## Pages et parcours utilisateur

### `/`
Ajout de liens directs AllDebrid ou magnets.  
Un item passe en **Completed** dès que `links_count > 0`.

---

## NAS & Scheduler

- Unlock JIT AllDebrid
- Création dossiers DSM si multi-fichiers
- Fallback destinations Download Station
- Persistance Redis (`nas_folder`, `ds_dest_mode`)
- Scheduler séparé

---

## API — Exemples

### POST /api/submit
```bash
curl -X POST http://localhost:5000/api/submit \
  -H 'Content-Type: application/json' \
  -d '{"items":["magnet:?xt=urn:btih:..."]}'
```

### POST /send_to_nas/<id>
```bash
curl -X POST -u ADMIN_USER:ADMIN_PASS \
  http://localhost:5000/send_to_nas/12345
```

---

## Configuration

Source de vérité : `.env.example`

---

## Sécurité

- TLS obligatoire si exposé
- Basic Auth uniquement admin
