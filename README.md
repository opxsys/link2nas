# Link2NAS

Link2NAS est un service auto-hébergé qui permet d’envoyer automatiquement des liens et magnets AllDebrid vers un NAS Synology (Download Station), avec une interface web et un scheduler indépendant.

Architecture **propre**, **séparée**, et **production-ready** (web + scheduler systemd).

---

## Fonctionnalités

- 🔗 Support **AllDebrid** (magnets, liens directs)
- 📦 Envoi automatique vers **Synology Download Station**
- 🖥️ Interface web Flask (admin + status)
- ⏱️ Scheduler APScheduler **séparé du web**
- 🧠 Stockage d’état via **Redis**
- 🔐 Sécurité :
  - secrets uniquement via `.env`
  - aucun secret loggé
  - admin en Basic Auth
- 🧩 Extension Chrome (optionnelle)
- 🚀 Déploiement via **systemd**

---

## Architecture

```
/opt/link2nas
├── app.py                  # Entrée Gunicorn (web)
├── scheduler_runner.py     # Entrée scheduler (APScheduler)
├── link2nas/
│   ├── config.py           # Configuration centralisée (Settings)
│   ├── webapp.py           # Routes Flask
│   ├── scheduler.py        # Jobs scheduler
│   ├── scheduler_jobs.py
│   ├── redis_store.py
│   ├── alldebrid.py
│   ├── synology.py
│   ├── status.py
│   ├── auth.py
│   └── utils.py
├── templates/
├── static/
├── extension/              # Extension Chrome (optionnel)
├── deploy/                 # Services systemd
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
- systemd

---

## Installation

### 1. Cloner

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

Web disponible sur :  
👉 http://localhost:5000

---

## Déploiement systemd (recommandé)

### Web

`/etc/systemd/system/link2nas-web.service`

```ini
[Unit]
Description=Link2NAS Web (Gunicorn)
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/link2nas
EnvironmentFile=/opt/link2nas/.env
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH=/opt/link2nas
ExecStart=/opt/link2nas/venv/bin/gunicorn \
  --bind 0.0.0.0:5000 \
  --workers 2 \
  --timeout 120 \
  app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

### Scheduler

`/etc/systemd/system/link2nas-scheduler.service`

```ini
[Unit]
Description=Link2NAS Scheduler
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/link2nas
EnvironmentFile=/opt/link2nas/.env
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONPATH=/opt/link2nas
Environment=SCHEDULER_ENABLED=1
ExecStart=/opt/link2nas/venv/bin/python /opt/link2nas/scheduler_runner.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Activation :

```bash
systemctl daemon-reload
systemctl enable --now link2nas-web
systemctl enable --now link2nas-scheduler
```

---

## Sécurité

- ❌ Aucun secret dans le code
- ❌ Aucun secret dans les logs
- ✅ `.env` ignoré par git
- ✅ `Settings.__repr__()` masque toutes les données sensibles

Vérification :

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
| `SCHEDULER_ENABLED` | Activé uniquement via le service scheduler |
| `ADMIN_UI_ENABLED` | Active l’UI admin |
| `MAX_UNLOCK_PER_RUN` | Limite par cycle scheduler |

---

## Licence

Projet personnel — fais-en ce que tu veux, mais **assume** 😉

---

## Statut

✅ Fonctionnel  
✅ Stable  
🚧 Extension Chrome en évolution

---

## Auteur

© 2025 Link2NAS contributors
