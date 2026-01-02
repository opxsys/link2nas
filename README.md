# Link2NAS

[![Latest Release](https://img.shields.io/github/v/release/opxsys/link2nas?label=release)](https://github.com/opxsys/link2nas/releases/latest)
[![Docker Image](https://img.shields.io/badge/docker-ghcr.io/opxsys/link2nas-blue?logo=docker)](https://github.com/opxsys/link2nas/pkgs/container/link2nas)
[![Docker Build](https://github.com/opxsys/link2nas/actions/workflows/docker.yml/badge.svg)](https://github.com/opxsys/link2nas/actions/workflows/docker.yml)

**Link2NAS** est un service **auto-hébergé**, robuste et orienté production, permettant d’envoyer automatiquement des **liens et magnets AllDebrid** vers un **NAS Synology (Download Station)**.

L’architecture est volontairement **séparée** (web / scheduler), **stateless côté applicatif**, avec un **état centralisé dans Redis**.

> Objectif : fiabilité, clarté, zéro bricolage, et déploiement propre (Docker ou systemd).

---

## Fonctionnalités principales

- 🔗 **Support AllDebrid complet**
  - Magnets
  - Liens directs
  - Déverrouillage JIT (just-in-time)
  - Gestion des redirectors / multi-liens
- 📦 **Envoi automatique vers Synology Download Station**
  - Support mono-fichier et multi-fichiers
  - Création de dossiers FileStation si nécessaire
  - Fallbacks maîtrisés sur les formats de destination DSM
- 🖥️ **Interface web Flask**
  - UI principale
  - Interface admin
  - Page statut détaillée (AllDebrid / Redis / DSM)
- ⏱️ **Scheduler APScheduler indépendant**
  - Aucun job dans le process web
  - Verrous Redis pour éviter les doublons
- 🧠 **Redis comme source de vérité**
  - État applicatif
  - État NAS (dossier, mode DSM retenu)
- 🔐 **Sécurité stricte**
  - Secrets uniquement via `.env`
  - Aucun secret loggé
  - Redaction automatique des URLs sensibles
- 🧩 **Extension navigateur (Chrome)**
- 🚀 **Déploiement**
  - Docker / docker-compose (**recommandé**)
  - systemd (bare-metal / VPS)

---

## Architecture globale

```
/opt/link2nas
├── app.py                  # Entrée web (Gunicorn / Flask)
├── scheduler_runner.py     # Entrée scheduler (APScheduler)
├── link2nas/               # Cœur applicatif
│   ├── config.py           # Chargement Settings (env → objets)
│   ├── logging_setup.py    # Logging centralisé
│   ├── alldebrid.py        # Client AllDebrid + redirectors
│   ├── redis_store.py      # Modèle d’état Redis
│   ├── nas_send.py         # Pipeline NAS (DSM + idempotence)
│   ├── synology_fs.py      # DSM WebAPI (Auth / FileStation / DS)
│   ├── synology.py         # Helpers legacy + ping DSM
│   ├── scheduler_jobs.py  # Logique métier scheduler
│   ├── status_checks.py   # Probes AllDebrid / Redis / DSM
│   ├── status.py           # Routes statut
│   ├── auth.py             # Auth admin (factory basée sur Settings)
│   ├── webapp.py           # App Flask + routes
│   ├── web_auth.py         # Décorateurs auth web
│   ├── web_helpers.py      # Helpers UI / redaction / payloads
│   ├── web_process.py      # Traitement des items (direct / batch)
│   └── web_admin_tools.py  # Outils admin (delete, maintenance)
├── templates/              # Templates Jinja2
├── static/                 # Assets statiques
├── extension/              # Extensions navigateur
├── deploy/
│   ├── docker/             # Déploiement Docker
│   └── systemd/            # Services systemd
├── docs/
│   └── Usage-API.md        # Documentation API & workflows
├── CHANGELOG.md            # Historique des changements
├── TODO.md                 # Backlog technique (actionnable)
├── .env.example            # Configuration d’exemple
└── requirements.txt
```

---


## Prérequis

- Linux (testé Debian / Ubuntu)
- Compte **AllDebrid**
- NAS **Synology** avec Download Station
- **Redis**
- **Docker** ou **systemd**

---

## Configuration minimale

Variables indispensables dans `.env` :

- `FLASK_SECRET_KEY`
- `ALLDEBRID_APIKEY`
- `SYNOLOGY_URL`
- `SYNOLOGY_USER`
- `SYNOLOGY_PASSWORD`
- `REDIS_HOST`

👉 Voir **`.env.example`** pour la liste complète, commentée et structurée.

---

## Déploiement (recommandé)

### 🐳 Docker

Deux options :
- Utiliser l’image officielle (GHCR)
- Construire localement via `docker-compose`

📖 Documentation :
- `deploy/docker/README.md`
- `README.docker.md`

---

## Déploiement systemd (installation native)

Pour un contrôle fin du système (VPS, serveur dédié).

📖 Voir :
```
deploy/systemd/README.md
```

---

## Documentation d’utilisation & API

📘 **[`docs/Usage-API.md`](./docs/Usage-API.md)**

Contenu :
- Parcours UI (`/`, `/admin`, `/status`)
- API REST réelle (routes, payloads, exemples `curl`)
- Workflow interne (status vs app_status, NAS pipeline)
- Configuration complète `.env`
- Sécurité et limites connues

👉 **Lecture recommandée avant toute intégration.**

---

## Changelog & roadmap

- 📄 **`CHANGELOG.md`**
  - Historique détaillé des versions
  - Refactors majeurs (AllDebrid, NAS, DSM, UI)
- 🛠️ **`TODO.md`**
  - Backlog technique priorisé
  - Améliorations sans bullshit
  - Points de durcissement, perf, observabilité

---

## Sécurité

- ❌ Aucun secret dans le code
- ❌ Aucun secret dans les logs
- ✅ `.env` ignoré par git
- ✅ Redaction automatique des URLs sensibles
- ⚠️ Basic Auth → **HTTPS fortement recommandé**

---

## Philosophie

- Un process = un rôle
- Pas de scheduler dans Gunicorn
- Redis comme source de vérité
- NAS traité de façon idempotente
- Déploiement explicite et auditable
- Pas de magie cachée

---

## Statut

✅ Fonctionnel  
✅ Stable  
🚧 Extension navigateur en évolution  

---

## Licence

Projet personnel.  
Utilisation et modification libres.  
Aucune garantie. Tu assumes.

---

## Auteur

© 2025 – Link2NAS contributors