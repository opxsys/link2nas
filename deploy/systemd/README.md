# Link2NAS — Déploiement systemd

## Prérequis
- Linux avec systemd
- Python ≥ 3.10
- Redis disponible

---

## Installation

```bash
sudo ./deploy/systemd/install.sh
```

---

## Configuration

```bash
cp .env.example .env
```

Configurer au minimum :
- `ALLDEBRID_APIKEY`
- `ADMIN_PASS`
- `FLASK_SECRET_KEY`

---

## Services

```bash
sudo systemctl start link2nas-web
sudo systemctl start link2nas-scheduler
```

```bash
sudo systemctl enable link2nas-web
sudo systemctl enable link2nas-scheduler
```

---

## Logs

```bash
journalctl -u link2nas-web -f
journalctl -u link2nas-scheduler -f
```
