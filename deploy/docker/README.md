# Link2NAS – Image Docker (GHCR)

Cette image Docker permet d’exécuter **Link2NAS** sans installation Python ni systemd.
Elle est destinée à une utilisation **simple, reproductible et isolée** via Docker ou Docker Compose.

Link2NAS agit comme un **pont entre AllDebrid et un NAS Synology (Download Station)**, avec :
- une **interface web**
- un **scheduler séparé** pour le traitement automatique

---

## À quoi sert l’image

L’image Docker Link2NAS permet de :

- Ajouter des **liens directs ou magnets AllDebrid**
- Générer automatiquement les liens de téléchargement
- Envoyer les téléchargements vers **Synology Download Station**
- Gérer l’état via **Redis**
- Exécuter le tout sans dépendance locale (Python, venv, systemd)

Deux conteneurs sont utilisés :
- **link2nas-web** : interface web
- **link2nas-scheduler** : traitement automatique (jobs)

---

## Variables `.env`

L’image **n’embarque aucun secret**.  
Toute la configuration se fait via un fichier `.env`.

Variables principales :

```env
# Web
FLASK_SECRET_KEY=change_me
ADMIN_USER=admin
ADMIN_PASS=change_me

# AllDebrid
ALLDEBRID_APIKEY=xxxxxxxxxxxxxxxx

# Redis
REDIS_HOST=redis
REDIS_PORT=6379

# NAS
NAS_ENABLED=true
SYNOLOGY_URL=http://nas:5000
SYNOLOGY_USER=admin
SYNOLOGY_PASSWORD=change_me

# Scheduler
SCHEDULER_ENABLED=true
```

➡️ Un fichier **`.env.example`** est fourni dans le dépôt.  
➡️ Le fichier `.env` peut être placé **où vous voulez** (chemin libre dans `docker-compose.yml`).

---

## Exemple `docker-compose.yml`

```yaml
version: "3.9"

services:
  redis:
    image: redis:7
    restart: unless-stopped

  link2nas-web:
    image: ghcr.io/opxsys/link2nas:latest
    container_name: link2nas-web
    env_file:
      - .env
    ports:
      - "5000:5000"
    depends_on:
      - redis
    restart: unless-stopped

  link2nas-scheduler:
    image: ghcr.io/opxsys/link2nas:latest
    container_name: link2nas-scheduler
    env_file:
      - .env
    environment:
      SCHEDULER_ENABLED: "1"
    depends_on:
      - redis
    restart: unless-stopped
```

Lancement :

```bash
docker compose up -d
```

---

## Ports exposés

| Port | Description |
|-----:|------------|
| 5000 | Interface Web Link2NAS |

---

## Volumes

Aucun volume **obligatoire**.

Optionnel (recommandé en production) :
- logs Docker (driver)
- sauvegarde Redis si Redis est externalisé

---

## Web + Scheduler (2 conteneurs)

Pourquoi deux conteneurs ?

- **Séparation claire des responsabilités**
- Le scheduler peut être redémarré sans impacter le web
- Évite les effets de bord (jobs bloquants, locks)

| Conteneur | Rôle |
|----------|------|
| link2nas-web | Interface web Flask |
| link2nas-scheduler | Jobs AllDebrid / NAS |

---

## Deux modes d’utilisation

### 1️⃣ Utiliser l’image GHCR (recommandé)
- Pas de build
- Mise à jour simple
- Déploiement rapide

### 2️⃣ Construire l’image soi-même
- À partir du `Dockerfile`
- Utile pour fork ou customisation

---

## Sécurité

- ❌ Aucun secret dans l’image
- ❌ Aucun secret dans le dépôt
- ✅ Secrets uniquement via `.env`
- ✅ Compatible reverse-proxy (Traefik, Nginx, etc.)

---

## Support

Projet personnel, **stable et utilisé en production**.  
À utiliser librement, à vos risques et périls 😉

---

© 2025 – Link2NAS
