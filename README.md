![image](https://github.com/user-attachments/assets/5e1a55be-3e5e-4196-ba39-5eb488c09afb)


# 🕷️ WebPhantom CLI

<p align="center">
  <img src="https://img.shields.io/badge/Kali-Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white" alt="Kali Linux"/>
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+"/>
  <img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="License: MIT"/>
</p>

<p align="center">
  <b>Outil de pentest web automatisé pour Kali Linux</b><br>
  <sub>🔍 Reconnaissance | 🔬 Scan de vulnérabilités | 🤖 Analyse IA | 🧪 Tests automatisés</sub>
</p>

---

## 📋 Description

**WebPhantom** est un outil en ligne de commande conçu pour **automatiser les tests de pénétration web** sur Kali Linux. Il permet de réaliser rapidement des reconnaissances, des scans de vulnérabilités et des analyses basées sur des patterns.

> ⚠️ **Avertissement** : Cet outil est destiné exclusivement à des fins légitimes telles que les tests de pénétration, la formation à la sensibilisation à la sécurité et l'évaluation des vulnérabilités. Toute utilisation non autorisée est illégale et contraire à l'éthique.

### 🔍 Fonctionnalités principales

- 🔎 **Reconnaissance automatisée** des applications web
- 🛡️ **Détection de vulnérabilités** (XSS, SQLi, LFI, etc.)
- 🧠 **Préparation pour l'intégration IA** (analyse basée sur des patterns)
- 📜 **Scénarios YAML** pour orchestrer des tests complets
- 🚀 **Extensible** par l'ajout de nouveaux modules et payloads
- 🔄 **Rapide et léger**, parfait pour les pentests rapides

## ⚙️ Installation

```bash
# Cloner le dépôt
git clone https://github.com/servais1983/WebPhantom.git
cd WebPhantom

# Rendre le script d'installation exécutable
chmod +x install.sh

# Lancer l'installation
./install.sh
```

L'installation met en place les dépendances nécessaires et prépare l'environnement d'exécution sur Kali Linux.

## 🛠️ Commandes

| Commande | Description | Exemple |
|----------|-------------|---------|
| `recon` | Analyse de surface (HTML, forms, scripts, headers) | `python3 webphantom.py recon http://site.test` |
| `scan` | Test de vulnérabilités simples (XSS, SQLi, LFI) | `python3 webphantom.py scan http://site.test` |
| `ai` | Analyse basée sur règles (prévu pour LLM local) | `python3 webphantom.py ai http://site.test` |
| `run` | Scénario YAML (pentest-as-code) | `python3 webphantom.py run scripts/basic_web_test.yaml` |

## 🚀 Exemple d'utilisation

### Reconnaissance d'un site web

```bash
python3 webphantom.py recon http://testphp.vulnweb.com
```

Cette commande analysera le site web et affichera des informations sur :
- Le code HTTP de la réponse
- Le type de serveur web
- Les formulaires détectés
- Les balises scripts trouvées

### Exécution d'un scénario complet

```bash
python3 webphantom.py run scripts/basic_web_test.yaml
```

Cette commande exécutera un scénario complet qui :
1. Effectue une reconnaissance du site cible
2. Teste les vulnérabilités courantes
3. Réalise une analyse basée sur des patterns

## 🗂️ Structure du projet

```
webphantom/
├── core/              # Modules principaux
│   ├── recon.py       # Module de reconnaissance
│   ├── vulns.py       # Scanner de vulnérabilités
│   ├── ai_analyzer.py # Analyseur basé sur patterns
│   └── utils.py       # Fonctions utilitaires
├── scripts/           # Scénarios prédéfinis
│   └── basic_web_test.yaml
├── webphantom.py      # Point d'entrée principal
├── requirements.txt   # Dépendances Python
├── install.sh         # Script d'installation
└── README.md          # Documentation
```

## 📈 Fonctionnalités à venir

- [ ] Intégration de modèles LLM locaux pour l'analyse
- [ ] Génération de rapports détaillés en HTML/PDF
- [ ] Scan de vulnérabilités plus avancé (CSRF, SSRF, etc.)
- [ ] Interface web pour visualiser les résultats
- [ ] Création de payloads personnalisés
- [ ] Support pour l'authentification (Basic, Forms, JWT)

## 🔒 Sécurité et Éthique

Ce projet est conçu pour des **tests de sécurité légitimes**. Utilisez-le uniquement avec une autorisation explicite dans le cadre de :

- ✅ Tests de pénétration autorisés
- ✅ Formations de sensibilisation
- ✅ Évaluations de sécurité internes
- ✅ Environnements de test et développement

## 🤝 Contribuer

Les contributions sont les bienvenues ! N'hésitez pas à ouvrir une issue ou à soumettre une pull request pour améliorer l'outil.

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier LICENSE pour plus de détails.

---

<p align="center">
  <sub>🔐 Développé pour promouvoir la sécurité web et les tests d'intrusion éthiques 🛡️</sub>
</p>
