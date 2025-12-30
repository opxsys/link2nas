# Link2NAS

Link2NAS est un service **auto‑hébergé**, robuste et production‑ready, permettant d’envoyer automatiquement des **liens et magnets AllDebrid** vers un **NAS Synology (Download Station)**.

L’architecture est volontairement **séparée** (web / scheduler), **stateless côté applicatif**, avec un stockage d’état centralisé via **Redis**.

> Objectif : fiabilité, clarté, zéro bricolage, et un déploiement propre (systemd ou Docker).

---

## Fonctionnalités principales

- 🔗 Support complet **AllDebrid**
  - Magnets
  - Liens directs
  - Déverrouillage JIT (just‑in‑time)
- 📦 Envoi automatique vers **Synology Download Station**
- 🖥️ Interface web Flask
  - UI admin
  - Vue statut détaillée (AllDebrid, Redis, NAS)
- ⏱️ Scheduler **APScheduler indépendant**
  - Aucun job dans le process web
- 🧠 Stockage d’état via **Redis**
- 🔐 Sécurité stricte
  - secrets uniquement via `.env`
  - aucun secret loggé
  - masquage automatique des valeurs sensibles
- 🧩 Extension Chrome (optionnelle)
- 🚀 Déploiement :
  - **Docker / docker‑compose (recommandé)**
  - **systemd (bare‑metal / VPS)**

---

## Architecture

```
/opt/link2nas
├── app.py                  # Entrée Gunicorn (web)
├── scheduler_runner.py     # Entrée scheduler (APScheduler)
├── link2nas/
│   ├── config.py
│   ├── webapp.py
│   ├── scheduler.py
│   ├── scheduler_jobs.py
│   ├── redis_store.py
│   ├── alldebrid.py
│   ├── synology.py
│   ├── status.py
│   ├── auth.py
│   └── utils.py
├── templates/
├── static/
├── extension/
├── deploy/
│   ├── docker/
│   └── systemd/
├── .env.example
└── requirements.txt
```

---

## Prérequis

- Linux (testé Debian / Ubuntu)
- Compte **AllDebrid**
- NAS **Synology** avec Download Station
- **Docker** ou **systemd**
- Redis (interne ou externe)

---

## Déploiement (recommandé)

### 🐳 Docker

Deux modes sont possibles :
- **Utiliser l’image Docker officielle (GHCR)**  
- **Construire localement via docker‑compose**

👉 Voir la documentation complète :
- `deploy/README.md`
- `deploy/docker/README.md`
- `README.docker.md` (image Docker uniquement)

---

## Déploiement systemd (installation native)

Pour une intégration système fine (serveur dédié, contraintes spécifiques).

👉 Voir :
```
deploy/systemd/README.md
```

---

## Documentation d’utilisation & API

La documentation fonctionnelle complète est disponible ici :

👉 **[`Link2NAS_Documentation_Usage_API.md`](./docs/Usage-API.md)**

Elle couvre :

- 📄 **Pages et parcours utilisateur**
  - `/` (UI principale)
  - `/admin` (interface admin)
  - `/status` (page état global)
- 🔌 **API REST réelle**
  - routes exactes (`GET` / `POST`)
  - payloads attendus
  - exemples `curl`
- 🔄 **Workflow interne**
  - différence `status` vs `app_status`
  - règles de terminaison
  - unlock AllDebrid JIT
  - verrous Redis
- ⚙️ **Configuration complète (`.env`)**
  - variables obligatoires / optionnelles
  - valeurs par défaut
  - impact sur le comportement
- 🔐 **Sécurité & limites**
  - Basic Auth
  - recommandations reverse-proxy
  - ce que l’application ne fait pas

👉 **À lire avant toute intégration (extension, API, automatisation).**
---
s

## Sécurité

- ❌ Aucun secret dans le code
- ❌ Aucun secret dans les logs
- ✅ `.env` ignoré par git
- ✅ Masquage automatique des secrets dans les logs

---

## Philosophie

- Un process = un rôle
- Pas de scheduler dans Gunicorn
- Redis comme source de vérité
- Déploiement explicite et auditable
- Zéro magie cachée

---

## Licence

Projet personnel.  
Utilisation libre, modifications libres.  
Aucune garantie. Tu assumes.

---

## Statut

✅ Fonctionnel  
✅ Stable  
🚧 Extension Chrome en évolution  

---

## Auteur

© 2025 – Link2NAS contributors
