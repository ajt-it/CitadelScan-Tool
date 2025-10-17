# 🛡️ CitadelScan Tool

**Audit non-intrusif Unix/Linux – lecture seule**  
Développé par **Citadel IT Solutions**, inspiré des recommandations **ISACA (2015)**  
et de référentiels publics de durcissement système.

---

## 📖 Description

CitadelScan est un script **Bash** en **lecture seule** qui collecte des informations
de sécurité sur les systèmes Unix/Linux.  
Il ne modifie **aucun paramètre système**.  
Les résultats sont enregistrés dans des fichiers texte et, optionnellement, au format HTML.

### Profils disponibles

| Profil | Description |
|--------|--------------|
| `isaca` | Vérifications issues de la méthodologie ISACA |
| `cis`   | Contrôles inspirés du CIS Benchmark |
| `full`  | Audit complet (ISACA + CIS + extensions internes) |

---

## ⚙️ Usage

```bash
sudo ./CitadelScanTool.sh --profile=isaca --output=/tmp/audit --html --banner=auto
```

### Options principales

| Option | Description |
|--------|--------------|
| `--profile` | Sélection du profil (`isaca`, `cis`, `full`) |
| `--output` | Répertoire de sortie |
| `--html` | Génère un rapport HTML en plus du TXT |
| `--banner` | Affiche la bannière ASCII du logo Citadel |

---

## 🧾 Exemples de sortie

- `/tmp/audit/report.txt`
- `/tmp/audit/report.html`
- `/tmp/audit/summary.txt` (résumé avec score et top-risques)

---

## 🔐 Sécurité

- Aucune écriture système (`read-only`)
- Aucun paquet installé ou supprimé
- Compatible Ubuntu, Debian, RHEL, CentOS, SUSE

---

## 🧩 Références

- ISACA, *Auditing Linux/Unix Systems: Lessons Learned*, 2015  
- CIS Benchmarks (Center for Internet Security)

---

## 🤝 Contributions

Les contributions sont les bienvenues : suggestions, issues, pull requests.  
Les propositions d’amélioration seront étudiées avec attention.

---

## 🪪 Licence

Ce projet est distribué sous la **Citadel Open License (Non-Commerciale)**.  
Il peut être librement utilisé, modifié ou redistribué à des fins non commerciales,  
avec attribution obligatoire à **Citadel IT Solutions (2025)**  
et mention de la source **ISACA (2015)**.

Voir le fichier [LICENSE.txt](LICENSE.txt) pour les conditions complètes.

---

## 📅 Version

- **v3.0 (Octobre 2025)**  
  Voir le [CHANGELOG](CHANGELOG.md).

---

# 🛡️ CitadelScan Tool (English)

**Read-only Unix/Linux audit script**  
Developed by **Citadel IT Solutions**, based on **ISACA (2015)** best practices  
and public Linux hardening references.

---

## 📖 Description

CitadelScan is a **read-only Bash script** that collects security and hardening
information on Unix/Linux systems.  
It makes **no system changes**.  
Reports are generated as plain text and optionally as HTML.

### Available Profiles

| Profile | Description |
|----------|--------------|
| `isaca` | Checks based on ISACA audit methodology |
| `cis` | Controls inspired by CIS Benchmark |
| `full` | Complete audit (ISACA + CIS + internal extensions) |

---

## ⚙️ Usage

```bash
sudo ./CitadelScanTool.sh --profile=isaca --output=/tmp/audit --html --banner=auto
```

### Main Options

| Option | Description |
|---------|-------------|
| `--profile` | Selects the audit profile (`isaca`, `cis`, `full`) |
| `--output` | Output directory |
| `--html` | Generates an additional HTML report |
| `--banner` | Displays the Citadel ASCII banner |

---

## 🧾 Sample Outputs

- `/tmp/audit/report.txt`
- `/tmp/audit/report.html`
- `/tmp/audit/summary.txt` (summary with score and top risks)

---

## 🔐 Security

- No system writes (`read-only`)
- No package installation or removal
- Compatible with Ubuntu, Debian, RHEL, CentOS, SUSE

---

## 🧩 References

- ISACA, *Auditing Linux/Unix Systems: Lessons Learned*, 2015  
- CIS Benchmarks (Center for Internet Security)

---

## 🤝 Contributions

Contributions are welcome — suggestions, issues, pull requests.  
All improvements will be reviewed carefully.

---

## 🪪 License

This project is distributed under the **Citadel Open License (Non-Commercial)**.  
It may be freely used, modified, and redistributed for non-commercial purposes,  
with mandatory attribution to **Citadel IT Solutions (2025)**  
and reference to **ISACA (2015)**.

See [LICENSE.txt](LICENSE.txt) for full license details.

---

## 📅 Version

- **v3.0 (October 2025)**  
  See [CHANGELOG](CHANGELOG.md).
