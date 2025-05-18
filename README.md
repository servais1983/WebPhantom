![image](https://github.com/user-attachments/files/14627644/WebPhantom.png)

# WebPhantom

WebPhantom est un outil de pentest web automatisé conçu pour la reconnaissance, l'analyse de vulnérabilités et la génération de rapports de sécurité.

## Fonctionnalités principales

- **Reconnaissance** : Collecte d'informations sur les applications web cibles
- **Scan de vulnérabilités** : Détection automatique des vulnérabilités web courantes
- **Scan avancé** : Détection de CSRF, SSRF, XXE, IDOR et autres vulnérabilités complexes
- **Analyse IA avec LLaMA** : Utilisation de modèles LLM locaux pour l'analyse contextuelle
- **Génération de rapports** : Création de rapports détaillés en formats HTML et PDF
- **Authentification** : Support pour Basic Auth, Forms et JWT avec gestion des utilisateurs
- **Charges utiles personnalisées** : Bibliothèque de payloads et transformations
- **Moteur de scénario YAML** : Automatisation des tests avec des scénarios personnalisables
- **Fuzzing** : Découverte de paramètres et endpoints vulnérables
- **Fingerprinting** : Identification précise des technologies utilisées
- **Tests SSL/TLS** : Analyse des configurations de sécurité

## Installation

### Prérequis

- Python 3.8+
- pip3

### Installation sur Kali Linux

En raison de la politique PEP 668 sur Kali Linux, il est recommandé d'utiliser un environnement virtuel :

```bash
# 1. Installer les dépendances système nécessaires
sudo apt-get update
sudo apt-get install -y build-essential

# 2. Cloner le dépôt
git clone https://github.com/servais1983/WebPhantom.git
cd WebPhantom

# 3. Créer et activer un environnement virtuel
python3 -m venv webphantom_env
source webphantom_env/bin/activate

# 4. Installer d'abord les dépendances de base
pip install requests beautifulsoup4 nltk pyjwt bcrypt

# 5. Installer toutes les dépendances
pip install -r requirements.txt
```

### Gestion de l'espace disque

**Important** : WebPhantom utilise des modèles LLM qui peuvent être volumineux. Assurez-vous d'avoir au moins 5 GB d'espace disque libre pour télécharger et utiliser les modèles LLaMA.

Si vous rencontrez des erreurs "No space left on device" :
1. Libérez de l'espace disque sur votre système
2. Utilisez l'option `--no-ai` pour désactiver l'analyse IA (à venir)
3. Utilisez un modèle plus léger via l'option `model` dans les scénarios YAML

## Utilisation

### Commandes de base

```bash
# Activer l'environnement virtuel (si vous utilisez Kali Linux)
source webphantom_env/bin/activate

# Reconnaissance d'une cible
python webphantom.py recon https://example.com

# Scan de vulnérabilités basiques
python webphantom.py scan https://example.com

# Analyse IA avec LLaMA
python webphantom.py ai https://example.com

# Exécuter un scénario YAML
python webphantom.py run scripts/advanced_web_test.yaml --target https://example.com
```

### Scénarios YAML avancés

WebPhantom permet d'automatiser les tests avec des scénarios YAML personnalisables :

```yaml
target: https://example.com
steps:
  - type: recon
  - type: fingerprint
  - type: scan
  - type: advanced-scan
    options:
      scan_csrf: true
      scan_ssrf: true
  - type: wait
    options:
      seconds: 2
  - type: fuzz
    options:
      type: api
      wordlist: common
  - type: ai
    options:
      model: llama-7b-q4
  - type: report
    options:
      format: pdf
```

Pour exécuter un scénario avec une cible spécifique :

```bash
# Option 1 : Utiliser l'option --target
python webphantom.py run scripts/advanced_web_test.yaml --target https://example.com

# Option 2 : Utiliser un argument positionnel
python webphantom.py run scripts/advanced_web_test.yaml https://example.com

# Option 3 : Définir la cible dans le fichier YAML lui-même
python webphantom.py run scripts/advanced_web_test.yaml
```

### Types d'étapes supportées

| Type | Description | Options |
|------|-------------|---------|
| recon | Reconnaissance de base | - |
| scan | Scan de vulnérabilités basiques | - |
| advanced-scan | Scan de vulnérabilités avancées | scan_csrf, scan_ssrf, scan_xxe, scan_idor, scan_ssti |
| auth | Authentification | type (basic, form, jwt, register), username, password, email, role |
| ai | Analyse IA avec LLaMA | model (llama-7b-q4, etc.) |
| payload | Génération de charges utiles | type (xss, sqli, etc.), transform (url, html, base64, etc.), output |
| report | Génération de rapports | format (html, pdf), output |
| fuzz | Fuzzing d'API et de paramètres | type (parameter, api), wordlist |
| fingerprint | Fingerprinting avancé | - |
| brute-force | Attaques par force brute | target (login, admin, etc.), wordlist |
| ssl-scan | Analyse SSL/TLS | - |
| dos-test | Tests de résistance DoS | - |
| wait | Attente entre les étapes | seconds |

## Modules principaux

### Analyse IA avec LLaMA
Le module `llm_integration.py` utilise NLTK et des modèles LLM locaux pour analyser les applications web :

- Téléchargement et vérification automatique des modèles
- Analyse contextuelle pour identifier des vulnérabilités complexes
- Génération de recommandations de sécurité

### Scan avancé de vulnérabilités
Le module `advanced_vulns.py` permet de détecter des vulnérabilités avancées :

- Cross-Site Request Forgery (CSRF)
- Server-Side Request Forgery (SSRF)
- XML External Entity (XXE)
- Insecure Direct Object References (IDOR)
- Server-Side Template Injection (SSTI)

### Générateur de rapports
Le module `report_generator.py` crée des rapports détaillés et lisibles :

- Formats HTML et PDF
- Résumé exécutif et détails techniques
- Graphiques et tableaux de synthèse
- Templates personnalisables

### Authentification
Le module `auth.py` gère l'authentification et les utilisateurs :

- Basic Auth, Forms et JWT
- Hachage sécurisé des mots de passe avec bcrypt
- Gestion des rôles et permissions

### Générateur de charges utiles
Le module `payload_generator.py` permet de créer et gérer des charges utiles personnalisées :

- Bibliothèque de charges utiles prédéfinies pour différents types d'attaques
- Création de charges utiles personnalisées
- Transformation des charges utiles (encodage URL, HTML, Base64, etc.)
- Obfuscation pour contourner les protections
- Organisation par catégories et ensembles

## Dépannage

Si vous rencontrez des problèmes lors de l'installation ou de l'utilisation de WebPhantom, consultez le fichier [TROUBLESHOOTING.md](TROUBLESHOOTING.md) pour des solutions aux problèmes courants.

## Licence

Ce projet est sous licence MIT.
