![image](https://github.com/user-attachments/assets/5e1a55be-3e5e-4196-ba39-5eb488c09afb)


# 🕷️ WebPhantom CLI

<p align="center">
  <img src="https://img.shields.io/badge/Kali-Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white" alt="Kali Linux"/>
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+"/>
  <img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="License: MIT"/>
</p>

<p align="center">
  <b>Outil de pentest web automatisé pour Kali Linux</b><br>
  <sub>🔍 Reconnaissance | 🔬 Scan de vulnérabilités | 🤖 Analyse IA | 🧪 Tests automatisés | 📊 Rapports détaillés</sub>
</p>

---

## 📋 Description

**WebPhantom** est un outil en ligne de commande conçu pour **automatiser les tests de pénétration web** sur Kali Linux. Il permet de réaliser rapidement des reconnaissances, des scans de vulnérabilités avancés, des analyses basées sur l'IA (LLaMA), et génère des rapports détaillés.

> ⚠️ **Avertissement** : Cet outil est destiné exclusivement à des fins légitimes telles que les tests de pénétration, la formation à la sensibilisation à la sécurité et l'évaluation des vulnérabilités. Toute utilisation non autorisée est illégale et contraire à l'éthique.

### 🔍 Fonctionnalités principales

- 🔎 **Reconnaissance automatisée** des applications web
- 🛡️ **Détection avancée de vulnérabilités** (XSS, SQLi, LFI, CSRF, SSRF, XXE, etc.)
- 🧠 **Analyse IA avec LLaMA** pour l'identification intelligente des vulnérabilités
- 📊 **Génération de rapports détaillés** en HTML/PDF avec haute lisibilité
- 🔐 **Gestion complète des utilisateurs et authentification** (Basic, Forms, JWT)
- 💣 **Création de charges utiles personnalisées** pour différents types d'attaques
- 📜 **Scénarios YAML** pour orchestrer des tests complets
- 🔍 **Fuzzing d'API et de paramètres** pour découvrir des vulnérabilités cachées
- 🔒 **Analyse SSL/TLS** pour vérifier la sécurité des connexions
- 🔨 **Tests de résistance DoS** pour évaluer la robustesse des applications
- 🚀 **Extensible** par l'ajout de nouveaux modules et payloads
- 🔄 **Rapide et léger**, parfait pour les pentests rapides

## ⚙️ Installation

### Installation avec environnement virtuel (recommandé pour Kali Linux)

En raison de la politique de gestion des paquets Python sur Kali Linux (PEP 668), il est recommandé d'utiliser un environnement virtuel :

```bash
# Cloner le dépôt
git clone https://github.com/servais1983/WebPhantom.git
cd WebPhantom

# Installer python3-venv si ce n'est pas déjà fait
sudo apt install python3-venv

# Créer un environnement virtuel
python3 -m venv webphantom_env

# Activer l'environnement virtuel
source webphantom_env/bin/activate

# Installer d'abord les dépendances de base
pip install requests beautifulsoup4 nltk

# Puis installer toutes les dépendances
pip install -r requirements.txt
```

### Installation manuelle (alternative, non recommandée sur Kali)

```bash
# Cloner le dépôt
git clone https://github.com/servais1983/WebPhantom.git
cd WebPhantom

# Rendre le script d'installation exécutable
chmod +x install.sh

# Lancer l'installation
./install.sh

# Installation manuelle des dépendances (sur Kali, utilisez --break-system-packages avec précaution)
pip install -r requirements.txt --break-system-packages
```

### 📦 Dépendances principales

- Python 3.8+
- llama-cpp-python (pour l'analyse IA)
- nltk (pour le traitement du langage naturel)
- weasyprint (pour la génération de PDF)
- pyjwt et bcrypt (pour l'authentification)
- requests et beautifulsoup4 (pour la reconnaissance web)
- pycryptodome (pour le chiffrement des charges utiles)

## 🛠️ Commandes

| Commande | Description | Exemple avec environnement virtuel |
|----------|-------------|-----------------------------------|
| `recon` | Analyse de surface (HTML, forms, scripts, headers) | `source webphantom_env/bin/activate && python webphantom.py recon http://testphp.vulnweb.com` |
| `scan` | Test de vulnérabilités simples (XSS, SQLi, LFI) | `source webphantom_env/bin/activate && python webphantom.py scan http://testphp.vulnweb.com` |
| `advanced-scan` | Scan avancé (CSRF, SSRF, XXE, etc.) | `source webphantom_env/bin/activate && python webphantom.py advanced-scan http://testphp.vulnweb.com` |
| `ai` | Analyse IA avec LLaMA | `source webphantom_env/bin/activate && python webphantom.py ai http://testphp.vulnweb.com` |
| `report` | Génération de rapport HTML/PDF | `source webphantom_env/bin/activate && python webphantom.py report results.json --format pdf --output rapport.pdf` |
| `payload` | Génération de charges utiles personnalisées | `source webphantom_env/bin/activate && python webphantom.py payload xss --transform url` |
| `auth` | Gestion des utilisateurs et authentification | `source webphantom_env/bin/activate && python webphantom.py auth register --username pentester --email pentester@example.com --role admin` |
| `run` | Scénario YAML (pentest-as-code) | `source webphantom_env/bin/activate && python webphantom.py run scripts/advanced_web_test.yaml --target http://testphp.vulnweb.com` |

## 🚀 Exemple d'utilisation

### Reconnaissance d'un site web

```bash
# Activer l'environnement virtuel
source webphantom_env/bin/activate

# Lancer la reconnaissance sur une cible spécifique
python webphantom.py recon http://testphp.vulnweb.com
```

Cette commande analysera le site web et affichera des informations sur :
- Le code HTTP de la réponse
- Le type de serveur web
- Les formulaires détectés
- Les balises scripts trouvées

### Scan avancé de vulnérabilités

```bash
# Activer l'environnement virtuel
source webphantom_env/bin/activate

# Lancer le scan avancé sur une cible spécifique
python webphantom.py advanced-scan http://testphp.vulnweb.com
```

Cette commande effectuera un scan approfondi pour détecter :
- Vulnérabilités CSRF
- Vulnérabilités SSRF
- Injections XXE
- Vulnérabilités IDOR
- Et bien d'autres...

### Analyse avec IA (LLaMA)

```bash
# Activer l'environnement virtuel
source webphantom_env/bin/activate

# Lancer l'analyse IA sur une cible spécifique
python webphantom.py ai http://testphp.vulnweb.com
```

Cette commande utilise le modèle LLaMA pour :
- Analyser le comportement de l'application
- Identifier des patterns de vulnérabilités complexes
- Suggérer des vecteurs d'attaque potentiels
- Fournir une analyse contextuelle

### Génération de rapport

```bash
# Activer l'environnement virtuel
source webphantom_env/bin/activate

# Générer un rapport PDF à partir des résultats de scan
python webphantom.py report scan_results.json --format pdf --output rapport_pentest.pdf
```

Cette commande génère un rapport détaillé avec :
- Résumé des vulnérabilités trouvées
- Détails techniques pour chaque vulnérabilité
- Captures d'écran et preuves
- Recommandations de correction

### Création de charges utiles personnalisées

```bash
# Activer l'environnement virtuel
source webphantom_env/bin/activate

# Créer un ensemble de charges utiles XSS personnalisées
python webphantom.py payload xss --create --name "XSS avancé" --output custom_xss.json
```

Cette commande permet de créer et gérer des charges utiles pour :
- XSS (Cross-Site Scripting)
- SQLi (Injection SQL)
- XXE (XML External Entity)
- CSRF (Cross-Site Request Forgery)
- Et d'autres types d'attaques

### Gestion des utilisateurs

```bash
# Activer l'environnement virtuel
source webphantom_env/bin/activate

# Créer un nouvel utilisateur avec le rôle admin
python webphantom.py auth register --username pentester --email pentester@example.com --role admin
```

Cette commande permet de gérer les utilisateurs avec :
- Création et gestion de comptes
- Attribution de rôles et permissions
- Authentification sécurisée
- Gestion des tokens JWT

### Exécution d'un scénario complet

```bash
# Activer l'environnement virtuel
source webphantom_env/bin/activate

# Exécuter le scénario avancé sur une cible spécifique
# Note: Vous pouvez spécifier la cible de trois façons différentes
python webphantom.py run scripts/advanced_web_test.yaml --target http://testphp.vulnweb.com
# OU
python webphantom.py run scripts/advanced_web_test.yaml http://testphp.vulnweb.com
# OU définir la cible dans le fichier YAML lui-même
```

Cette commande exécutera un scénario complet qui :
1. Effectue une reconnaissance du site cible
2. Teste les vulnérabilités avancées
3. Réalise une analyse avec LLaMA
4. Génère un rapport détaillé

## 📜 Scénarios YAML avancés

WebPhantom prend en charge des scénarios YAML avancés pour automatiser des tests de pénétration complets. Voici un exemple de scénario avancé :

```yaml
target: https://example.com
steps:
  - type: recon
  - type: fingerprint
    options:
      detailed: true
  - type: scan
  - type: wait
    options:
      seconds: 2
  - type: advanced-scan
    options:
      scan_csrf: true
      scan_ssrf: true
      scan_xxe: true
  - type: fuzz
    options:
      type: api
      wordlist: common
  - type: ssl-scan
  - type: brute-force
    options:
      target: login
      wordlist: common
  - type: ai
    options:
      model: llama-7b-q4
  - type: report
    options:
      format: pdf
```

### Types d'étapes supportées

| Type d'étape | Description | Options |
|--------------|-------------|---------|
| `recon` | Reconnaissance de base | - |
| `scan` | Scan de vulnérabilités basiques | - |
| `advanced-scan` | Scan de vulnérabilités avancées | `scan_csrf`, `scan_ssrf`, `scan_xxe`, `scan_idor` |
| `ai` / `ai_analysis` | Analyse IA avec LLaMA | `model` |
| `auth` | Gestion de l'authentification | `type`, `username`, `password`, `email`, `role` |
| `payload` | Génération de charges utiles | `type`, `transform`, `output` |
| `report` | Génération de rapports | `format`, `output` |
| `fuzz` | Fuzzing d'API et de paramètres | `type` (`parameter` ou `api`), `wordlist` |
| `fingerprint` | Fingerprinting avancé | `detailed` |
| `brute-force` | Attaque par force brute | `target`, `wordlist` |
| `ssl-scan` | Analyse SSL/TLS | - |
| `dos-test` | Test de résistance aux attaques DoS | - |
| `wait` | Attente entre les étapes | `seconds` |

### Sauvegarde des résultats

Les résultats de chaque scénario sont automatiquement sauvegardés dans un dossier horodaté (`results_YYYYMMDD_HHMMSS/`) contenant :
- Un fichier JSON avec tous les résultats (`results.json`)
- Les rapports générés au format spécifié
- Les charges utiles personnalisées créées

## 🗂️ Structure du projet

```
webphantom/
├── core/                    # Modules principaux
│   ├── recon.py             # Module de reconnaissance
│   ├── vulns.py             # Scanner de vulnérabilités basiques
│   ├── advanced_vulns.py    # Scanner de vulnérabilités avancées
│   ├── llm_integration.py   # Intégration du modèle LLaMA
│   ├── report_generator.py  # Générateur de rapports HTML/PDF
│   ├── auth.py              # Gestion des utilisateurs et authentification
│   ├── payload_generator.py # Générateur de charges utiles personnalisées
│   └── utils.py             # Fonctions utilitaires et moteur de scénario
├── scripts/                 # Scénarios prédéfinis
│   ├── basic_web_test.yaml
│   └── advanced_web_test.yaml
├── templates/               # Templates pour les rapports
│   └── report_template.html
├── tests.py                 # Tests unitaires
├── webphantom.py            # Point d'entrée principal
├── requirements.txt         # Dépendances Python
├── requirements_minimal.txt # Dépendances minimales
├── TROUBLESHOOTING.md       # Guide de dépannage
├── install.sh               # Script d'installation
└── README.md                # Documentation
```

## 📊 Modules principaux

### 🧠 Module d'intégration LLaMA

Le module `llm_integration.py` permet d'utiliser le modèle LLaMA pour analyser les applications web et identifier des vulnérabilités complexes :

- Téléchargement et vérification automatique des modèles
- Prétraitement du texte avec NLTK pour une analyse optimisée
- Analyse contextuelle du code source et des réponses HTTP
- Identification de patterns de vulnérabilités non détectables par des scanners traditionnels
- Suggestions d'exploitation et recommandations de correction

### 🔍 Scanner de vulnérabilités avancées

Le module `advanced_vulns.py` étend les capacités de scan avec :

- Détection de CSRF (Cross-Site Request Forgery)
- Détection de SSRF (Server-Side Request Forgery)
- Détection d'injections XXE (XML External Entity)
- Détection de vulnérabilités IDOR (Insecure Direct Object References)
- Détection d'injections de template (SSTI)
- Et bien d'autres vulnérabilités avancées

### 📄 Générateur de rapports

Le module `report_generator.py` crée des rapports détaillés et hautement lisibles :

- Formats HTML et PDF
- Résumé exécutif pour les décideurs
- Détails techniques pour les équipes de développement
- Captures d'écran et preuves de concept
- Recommandations de correction priorisées
- Métriques de sévérité (CVSS)

### 🔐 Gestion des utilisateurs et authentification

Le module `auth.py` fournit une gestion complète des utilisateurs :

- Création et gestion de comptes utilisateurs
- Hachage sécurisé des mots de passe avec bcrypt
- Authentification via Basic Auth, formulaires et JWT
- Gestion des rôles et permissions
- Protection contre les attaques par force brute

### 💣 Générateur de charges utiles

Le module `payload_generator.py` permet de créer et gérer des charges utiles personnalisées :

- Bibliothèque de charges utiles prédéfinies pour différents types d'attaques
- Création de charges utiles personnalisées
- Transformation des charges utiles (encodage URL, HTML, Base64, etc.)
- Obfuscation pour contourner les protections
- Organisation par catégories et ensembles

### 🔍 Moteur de scénario YAML

Le module `utils.py` contient un moteur de scénario avancé qui :

- Exécute des scénarios de test complets à partir de fichiers YAML
- Prend en charge de nombreux types d'étapes (recon, scan, ai, auth, etc.)
- Permet de spécifier des options pour chaque étape
- Sauvegarde automatiquement les résultats dans un dossier horodaté
- Génère un fichier JSON avec tous les résultats

## 🔒 Sécurité et Éthique

Ce projet est conçu pour des **tests de sécurité légitimes**. Utilisez-le uniquement avec une autorisation explicite dans le cadre de :

- ✅ Tests de pénétration autorisés
- ✅ Formations de sensibilisation
- ✅ Évaluations de sécurité internes
- ✅ Environnements de test et développement

## 🤝 Contribuer

Les contributions sont les bienvenues ! N'hésitez pas à ouvrir une issue ou à soumettre une pull request pour améliorer l'outil.

1. Forkez le projet
2. Créez votre branche de fonctionnalité (`git checkout -b feature/amazing-feature`)
3. Committez vos changements (`git commit -m 'Add some amazing feature'`)
4. Poussez vers la branche (`git push origin feature/amazing-feature`)
5. Ouvrez une Pull Request

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier LICENSE pour plus de détails.

---

<p align="center">
  <sub>🔐 Développé pour promouvoir la sécurité web et les tests d'intrusion éthiques 🛡️</sub>
</p>
