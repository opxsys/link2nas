# Link2NAS — Docker (docker-compose depuis le dépôt)

## Prérequis
- Docker + Docker Compose (plugin)
- Un fichier `.env` à la racine du repo (non versionné), basé sur `.env.example`

> Ce document décrit le déploiement Docker **depuis le dépôt source**.
> Pour utiliser l’image pré-buildée GHCR, voir `README.docker.md` à la racine.

## Démarrage
Depuis la racine du projet :

```bash
cp .env.example .env
# édite .env (ALLDEBRID_APIKEY, SYNOLOGY_*, ADMIN_PASS, FLASK_SECRET_KEY…)
docker compose -f deploy/docker/docker-compose.yml up -d --build
```

## Accès
- Web UI : http://localhost:5000
- Status : http://localhost:5000/status (si STATUS_ROUTE_ENABLED=1)

## Logs
```bash
docker compose -f deploy/docker/docker-compose.yml logs -f web
docker compose -f deploy/docker/docker-compose.yml logs -f scheduler
```

## Arrêt
```bash
docker compose -f deploy/docker/docker-compose.yml down
```

## Architecture
- `web` : API + UI Flask (Gunicorn)
- `scheduler` : APScheduler (process séparé)
- `redis` : stockage d’état (files, locks, cache)

## Points importants
- Le **scheduler** est **désactivé** dans `web` (`SCHEDULER_ENABLED=0`)
- Le **scheduler** est **activé uniquement** dans le service `scheduler`
- Aucun secret n’est embarqué dans l’image Docker
- Les logs sortent sur stdout/stderr (Docker logs)

## Personnalisation
- Pour un Redis externe : supprime le service `redis` et ajuste `REDIS_HOST`
- Pour exposer derrière un reverse-proxy : retire le mapping `ports` et utilise le réseau Docker