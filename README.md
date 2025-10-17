# CitadelScan Tool

**Audit non-intrusif Unix/Linux – lecture seule**  
Développé par **Citadel IT Solutions**, inspiré des recommandations **ISACA (2015)** et de référentiels publics de durcissement système.

---

## Description

CitadelScan est un script **Bash** en **lecture seule** qui collecte des informations de sécurité sur les systèmes Unix/Linux.  
Il ne modifie **aucun paramètre système**.  
Les résultats sont enregistrés dans des fichiers texte et, optionnellement, au format HTML.

### Profils disponibles

| Profil | Description |
|--------|--------------|
| `isaca` | Vérifications issues de la méthodologie ISACA |
| `cis`   | Contrôles inspirés du CIS Benchmark |
| `full`  | Audit complet (ISACA + CIS + extensions internes) |

---

## Usage

```bash
sudo ./CitadelScanTool.sh --profile=isaca --output=/tmp/audit --html --banner=auto

---

## Licence

Ce projet est distribué sous la **Citadel Open License (Non-Commerciale)**.  
Il peut être librement utilisé, modifié ou redistribué à des fins non commerciales,  
avec attribution obligatoire à **Citadel IT Solutions** et mention de la source ISACA (2015).