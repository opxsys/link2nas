# Déploiement Link2NAS

Ce dossier regroupe les **différentes méthodes de déploiement** de Link2NAS.

Deux modes sont supportés :

---

## 🐳 Docker (recommandé)

- Déploiement isolé, reproductible  
- Aucune dépendance système hors Docker  
- Idéal pour serveurs personnels, NAS, VPS  

👉 **Voir : `README.docker.md`** (utilisation des images Docker officielles)

ℹ️ Pour builder l’image localement à partir du code source :  
👉 `deploy/docker/README.md`

---

## 🖥 systemd (installation native)

- Exécution directe sur l’hôte  
- Utilise un virtualenv Python  
- Plus flexible, mais plus dépendant du système  

👉 **Voir : `deploy/systemd/README.md`**

---

## Choix recommandé

| Usage | Méthode |
|------|--------|
| NAS / homelab | Docker |
| Serveur dédié | Docker |
| Intégration système avancée | systemd |

Les deux méthodes utilisent le **même fichier `.env` à la racine du projet**.
