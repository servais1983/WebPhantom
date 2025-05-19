![image](https://github.com/user-attachments/assets/e9aba812-6d5c-43a2-905e-6809d37c321b)


# WebPhantom 🕸️ 🔍

WebPhantom est un outil de pentest web automatisé conçu pour la reconnaissance, l'analyse de vulnérabilités et la génération de rapports de sécurité.

## Fonctionnalités principales

- 🔍 **Reconnaissance** : Collecte d'informations sur les applications web cibles
- 🛡️ **Scan de vulnérabilités** : Détection automatique des vulnérabilités web courantes
- 🔬 **Scan avancé** : Détection de CSRF, SSRF, XXE, IDOR et autres vulnérabilités complexes
- 🧠 **Analyse IA avec LLaMA** : Utilisation de modèles LLM locaux pour l'analyse contextuelle
- 📊 **Génération de rapports** : Création de rapports détaillés en formats HTML et PDF
- 🔐 **Authentification** : Support pour Basic Auth, Forms et JWT avec gestion des utilisateurs
- 💣 **Charges utiles personnalisées** : Bibliothèque de payloads et transformations
- 📜 **Moteur de scénario YAML** : Automatisation des tests avec des scénarios personnalisables
- 🔮 **Fuzzing** : Découverte de paramètres et endpoints vulnérables
- 👁️ **Fingerprinting** : Identification précise des technologies utilisées
- 🔒 **Tests SSL/TLS** : Analyse des configurations de sécurité
- 🌐 **Scan IP complet** : Analyse de plages d'adresses IP avec multiples outils de sécurité
- 🔄 **Intégration multi-outils** : Support pour Nmap, OpenVAS, Nikto, OWASP ZAP, TestSSL.sh, SNMP-check, Hydra, SSLyze, WPScan, Dirb/Dirbuster, Gobuster et Nuclei
- 🚀 **Commande unifiée** : Exécution de tous les outils en une seule commande

## Installation

### Prérequis

- Python 3.8+
- pip3
- Au moins 5 GB d'espace disque libre pour les modèles LLaMA

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

# 4. Installer d'abord les dépendances critiques une par une
# IMPORTANT : Cette étape est cruciale pour éviter les erreurs d'importation
pip install requests
pip install beautifulsoup4
pip install nltk
pip install pyjwt
pip install bcrypt

# 5. Installer toutes les dépendances restantes
pip install -r requirements.txt

# 6. Installer les outils externes nécessaires pour le scan IP
python3 webphantom.py install-tools
```

### Installation sans environnement virtuel (non recommandé)

Si vous ne souhaitez pas utiliser d'environnement virtuel sur Kali Linux :

```bash
# Utiliser l'option --break-system-packages pour contourner la politique PEP 668
pip install nltk requests beautifulsoup4 pyjwt bcrypt --break-system-packages
pip install -r requirements.txt --break-system-packages
```

### Gestion de l'espace disque

**Important** : WebPhantom utilise des modèles LLM qui peuvent être volumineux. Assurez-vous d'avoir au moins 5 GB d'espace disque libre pour télécharger et utiliser les modèles LLaMA.

Si vous rencontrez des erreurs "No space left on device" :

1. **Vérifiez votre espace disque disponible** :
   ```bash
   df -h
   ```

2. **Libérez de l'espace** :
   ```bash
   sudo apt-get clean
   sudo apt-get autoremove -y
   sudo journalctl --vacuum-time=1d
   ```

3. **Utilisez un modèle plus léger** dans votre fichier YAML :
   ```yaml
   - type: ai
     options:
       model: llama-3b-q4  # Modèle plus léger
   ```

4. **Redimensionnez votre partition** si vous utilisez une VM :
   - Si votre disque virtuel est plus grand que votre partition (vérifiez avec `sudo fdisk -l`), utilisez GParted pour étendre la partition.

5. **Utilisez un répertoire alternatif** pour les modèles :
   ```bash
   # Créer un lien symbolique vers un disque externe ou un répertoire avec plus d'espace
   mkdir -p /chemin/avec/espace/webphantom_models
   ln -sf /chemin/avec/espace/webphantom_models ~/.webphantom/models
   ```

## Utilisation

### ⚠️ Exécution avec sudo requise

**IMPORTANT** : Tous les outils de scan IP et de sécurité nécessitent des droits administrateur pour fonctionner correctement. Vous devez exécuter WebPhantom avec `sudo` pour les commandes de scan IP et d'outils de sécurité.

```bash
# Installer tous les outils nécessaires (avec sudo)
sudo python webphantom.py install-tools

# Scanner une adresse IP ou une plage d'adresses IP (avec sudo)
sudo python webphantom.py ip-scan 192.168.1.1

# Scanner une plage d'adresses IP (avec sudo)
sudo python webphantom.py ip-scan 192.168.1.0/24

# Exécuter tous les outils de scan sur une cible (avec sudo)
sudo python webphantom.py all-tools 192.168.1.1
```

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

### Scan IP et intégration multi-outils

WebPhantom intègre désormais un module complet de scan IP qui permet d'analyser des adresses IP individuelles ou des plages d'adresses IP complètes avec différents outils de sécurité :

```bash
# Scanner une adresse IP avec tous les outils disponibles
python webphantom.py all-tools 192.168.1.1

# Scanner une plage d'adresses IP avec des outils spécifiques
python webphantom.py ip-scan 192.168.1.0/24 --tools nmap nikto testssl

# Exécuter un scénario YAML incluant des scans IP
python webphantom.py run scripts/all_tools_scan.yaml
```

Exemple de scénario YAML pour le scan IP :

```yaml
target: 192.168.1.0/24
steps:
  - type: ip-scan
    options:
      tools:
        - nmap
        - nikto
        - testssl
  - type: wait
    options:
      seconds: 2
  - type: all-tools
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
| ip-scan | Scan d'adresses IP | tools (liste d'outils à utiliser) |
| all-tools | Exécution de tous les outils | - |

## Modules principaux

### 🧠 Analyse IA avec LLaMA
Le module `llm_integration.py` utilise NLTK et des modèles LLM locaux pour analyser les applications web :

- Téléchargement et vérification automatique des modèles
- Analyse contextuelle pour identifier des vulnérabilités complexes
- Génération de recommandations de sécurité

### 🔬 Scan avancé de vulnérabilités
Le module `advanced_vulns.py` permet de détecter des vulnérabilités avancées :

- Cross-Site Request Forgery (CSRF)
- Server-Side Request Forgery (SSRF)
- XML External Entity (XXE)
- Insecure Direct Object References (IDOR)
- Server-Side Template Injection (SSTI)

### 📊 Générateur de rapports
Le module `report_generator.py` crée des rapports détaillés et lisibles :

- Formats HTML et PDF
- Résumé exécutif et détails techniques
- Graphiques et tableaux de synthèse
- Templates personnalisables

### 🔐 Authentification
Le module `auth.py` gère l'authentification et les utilisateurs :

- Basic Auth, Forms et JWT
- Hachage sécurisé des mots de passe avec bcrypt
- Gestion des rôles et permissions

### 💣 Générateur de charges utiles
Le module `payload_generator.py` permet de créer et gérer des charges utiles personnalisées :

- Bibliothèque de charges utiles prédéfinies pour différents types d'attaques
- Création de charges utiles personnalisées
- Transformation des charges utiles (encodage URL, HTML, Base64, etc.)
- Obfuscation pour contourner les protections
- Organisation par catégories et ensembles

### 🌐 Scanner IP
Le nouveau module `ip_scanner.py` permet d'analyser des adresses IP et des plages d'adresses IP :

- Support pour les adresses IP individuelles et les plages CIDR
- Intégration de multiples outils de sécurité (Nmap, Nikto, TestSSL, etc.)
- Installation automatique des outils nécessaires
- Génération de rapports HTML détaillés
- Exécution parallèle pour optimiser les performances
- Analyse et formatage des résultats pour une meilleure lisibilité

## Outils intégrés

WebPhantom intègre désormais les outils suivants pour le scan IP et l'analyse de sécurité :

| Outil | Description |
|-------|-------------|
| Nmap | Scanner réseau avancé pour la découverte de services et la détection de versions |
| OpenVAS | Scanner de vulnérabilités complet |
| Nikto | Scanner de vulnérabilités web |
| OWASP ZAP | Proxy d'interception et scanner de vulnérabilités web |
| TestSSL.sh | Vérification de la configuration SSL/TLS |
| SNMP-check | Vérification des configurations SNMP |
| Hydra | Outil de brute force pour les services réseau |
| SSLyze | Analyse avancée des configurations SSL/TLS |
| WPScan | Scanner de vulnérabilités WordPress |
| Dirb/Dirbuster | Découverte de répertoires et fichiers web |
| Gobuster | Découverte de répertoires et fichiers web (alternative à dirb) |
| Nuclei | Scanner de vulnérabilités basé sur des templates |

## Résolution des problèmes courants

### Erreur "ModuleNotFoundError: No module named 'nltk'"

Si vous rencontrez cette erreur, c'est que NLTK n'est pas installé :

```bash
# Dans l'environnement virtuel
pip install nltk

# Sans environnement virtuel sur Kali Linux
pip install nltk --break-system-packages
```

### Erreur "No space left on device" lors du téléchargement des modèles

Cette erreur indique que vous n'avez pas assez d'espace disque :

1. Vérifiez l'espace disponible : `df -h`
2. Libérez de l'espace : `sudo apt-get clean && sudo apt-get autoremove -y`
3. Utilisez un modèle plus léger dans votre fichier YAML
4. Redimensionnez votre partition si vous utilisez une VM

### Erreur "externally-managed-environment" sur Kali Linux

Cette erreur est due à la politique PEP 668 de Kali Linux :

1. Utilisez un environnement virtuel (recommandé)
2. Ou utilisez l'option `--break-system-packages` avec pip

### Erreur lors de l'installation des outils externes

Si vous rencontrez des erreurs lors de l'installation des outils externes :

```bash
# Assurez-vous que votre système est à jour
sudo apt-get update && sudo apt-get upgrade -y

# Installez les outils manuellement
sudo apt-get install -y nmap nikto testssl.sh snmp-check hydra sslyze wpscan dirb gobuster
```

Pour plus de détails sur la résolution des problèmes, consultez le fichier [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Licence

Ce projet est sous licence MIT.
