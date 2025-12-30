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
  - **systemd (recommandé en bare‑metal / VPS)**
  - **Docker / docker‑compose**

---

## Architecture

```
/opt/link2nas
├── app.py                  # Entrée Gunicorn (web)
├── scheduler_runner.py     # Entrée scheduler (APScheduler)
├── link2nas/
│   ├── config.py           # Configuration centralisée (Settings)
│   ├── webapp.py           # Routes Flask + API
│   ├── scheduler.py        # Orchestration APScheduler
│   ├── scheduler_jobs.py   # Jobs métier
│   ├── redis_store.py      # Accès Redis
│   ├── alldebrid.py        # API AllDebrid
│   ├── synology.py         # API Synology Download Station
│   ├── status.py           # Health / status global
│   ├── auth.py             # Auth admin
│   └── utils.py
├── templates/
├── static/
├── extension/              # Extension Chrome (optionnelle)
├── deploy/
│   ├── docker/             # Déploiement Docker
│   └── systemd/            # Déploiement systemd
├── .env.example
└── requirements.txt
```

---

## Prérequis

- Linux (testé Debian / Ubuntu)
- Python **3.10+**
- Redis
- Compte **AllDebrid**
- NAS **Synology** avec Download Station
- systemd **ou** Docker

---

## Installation (classique)

### 1. Cloner le dépôt

```bash
git clone https://github.com/<user>/link2nas.git
cd link2nas
```

### 2. Virtualenv

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configuration

```bash
cp .env.example .env
nano .env
```

⚠️ **Tous les secrets sont obligatoires** :

- `FLASK_SECRET_KEY`
- `ADMIN_PASS`
- `ALLDEBRID_APIKEY`
- `SYNOLOGY_PASSWORD`

---

## Lancement en développement

```bash
set -a
source .env
set +a
python app.py
```

👉 Web : http://localhost:5000

---

## Déploiement systemd (recommandé)

Les fichiers sont fournis dans `deploy/systemd/`.

### Installation

```bash
cd deploy/systemd
sudo ./install.sh
```

Cela installe et active :

- `link2nas-web.service`
- `link2nas-scheduler.service`

### Gestion

```bash
systemctl status link2nas-web
systemctl status link2nas-scheduler

journalctl -u link2nas-web -f
journalctl -u link2nas-scheduler -f
```

---

## Déploiement Docker

Voir le README dédié :

```
deploy/docker/README.md
```

En résumé :

```bash
cd deploy/docker
cp .env.example .env
docker compose up -d
```

Aucune image pré‑buildée : le `Dockerfile` est utilisé automatiquement.

---

## Sécurité

- ❌ Aucun secret dans le code
- ❌ Aucun secret dans les logs
- ✅ `.env` ignoré par git
- ✅ `Settings.__repr__()` masque les secrets

Test rapide :

```bash
python - <<'EOF'
from link2nas.config import Settings
s = Settings.from_env()
print(s)
EOF
```

---

## Variables importantes

| Variable | Description |
|--------|-------------|
| `NAS_ENABLED` | Active l’envoi vers le NAS |
| `SCHEDULER_ENABLED` | Activé uniquement côté scheduler |
| `ADMIN_UI_ENABLED` | Active l’interface admin |
| `MAX_UNLOCK_PER_RUN` | Limite AllDebrid par cycle |
| `STATUS_ROUTE_ENABLED` | Active `/api/status` |

---

## Philosophie

- Un process = un rôle
- Pas de logique métier dans l’UI
- Pas de scheduler dans Gunicorn
- Redis comme source de vérité
- Déploiement lisible et auditable

---

## Licence

Projet personnel.  
Utilisation libre, modifications libres.  
Pas de garantie. Tu assumes.

---

## Statut

✅ Fonctionnel  
✅ Stable  
🚧 Extension Chrome en évolution  

---

## Auteur

© 2025 – Link2NAS contributors
