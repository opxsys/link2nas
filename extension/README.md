# Link2NAS – Browser Extensions

Ce dossier contient les extensions navigateur pour **Link2NAS**.

Les extensions permettent d’envoyer rapidement des liens (magnets, URLs AllDebrid, etc.)
vers l’instance Link2NAS, directement depuis le navigateur.

---

## Structure

```
extension/
├── chrome/
│   ├── manifest.json
│   ├── background.js
│   ├── content.js
│   ├── popup.html
│   ├── popup.js
│   ├── icon.png
│   └── README.md
└── firefox/
    └── (à venir)
```

---

## Chrome / Chromium

Chemin : `extension/chrome`

- Extension fonctionnelle
- Compatible Chrome / Chromium / Brave / Edge
- Basée sur Manifest V3
- Documentation complète dans :

extension/chrome/README.md

### Installation (mode développeur)

1. Ouvrir `chrome://extensions`
2. Activer **Mode développeur**
3. Cliquer sur **Charger l’extension non empaquetée**
4. Sélectionner le dossier `extension/chrome`

---

## Firefox (prévu)

Chemin : `extension/firefox`

- Pas encore implémenté
- Prévu ultérieurement
- Adaptation de la version Chrome :
  - compatibilité WebExtension
  - ajustements du manifest
  - éventuel mapping `chrome.*` → `browser.*`

Le dossier est présent volontairement pour clarifier la roadmap.

---

## Notes

- Les extensions sont optionnelles
- Le backend Link2NAS fonctionne sans extension
- Aucune donnée sensible n’est embarquée
- La configuration se fait côté utilisateur

---

## Licence

Les extensions suivent la même licence que le projet Link2NAS.
