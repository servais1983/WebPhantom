# Guide de dépannage pour WebPhantom

Ce document fournit des solutions aux problèmes courants rencontrés lors de l'installation et de l'utilisation de WebPhantom, particulièrement sur Kali Linux.

## Problèmes d'installation

### Erreur "externally-managed-environment" sur Kali Linux

**Problème** : Lors de l'installation des dépendances avec pip, vous obtenez l'erreur "externally-managed-environment".

**Solution** : Utilisez un environnement virtuel Python comme recommandé dans le README :

```bash
# Installer python3-venv
sudo apt install python3-venv

# Créer un environnement virtuel
python3 -m venv webphantom_env

# Activer l'environnement virtuel
source webphantom_env/bin/activate

# Installer les dépendances
pip install -r requirements.txt
```

### Erreur lors de l'installation des dépendances système

**Problème** : Lors de l'installation des dépendances, vous obtenez des erreurs liées aux dépendances système.

**Solution** : Installez les dépendances système nécessaires et vérifiez leur installation :

```bash
# Installer les dépendances système
sudo apt-get update
sudo apt-get install -y cmake pkg-config build-essential

# Vérifier que cmake est bien installé
which cmake
# Devrait afficher quelque chose comme /usr/bin/cmake

# Réessayer l'installation des dépendances Python
source webphantom_env/bin/activate  # Si ce n'est pas déjà fait
pip install -r requirements.txt
```

### Erreur "ModuleNotFoundError: No module named 'requests'"

**Problème** : Lors de l'exécution de WebPhantom, vous obtenez une erreur indiquant que le module 'requests' n'est pas trouvé.

**Solution** : Installez d'abord les dépendances de base séparément :

```bash
# Activer l'environnement virtuel
source webphantom_env/bin/activate

# Installer les dépendances de base
pip install requests beautifulsoup4 pyjwt bcrypt nltk

# Puis installer les autres dépendances
pip install -r requirements.txt
```

### Installation progressive des dépendances

Si vous rencontrez des problèmes avec l'installation complète, essayez d'installer les dépendances progressivement :

```bash
# Activer l'environnement virtuel
source webphantom_env/bin/activate

# Installer les dépendances une par une
pip install requests
pip install beautifulsoup4
pip install pyjwt
pip install bcrypt
pip install nltk
pip install llama-cpp-python
pip install weasyprint
pip install pycryptodome
pip install PyYAML
pip install Jinja2
pip install Markdown
pip install tqdm
pip install colorama
```

## Vérification de l'installation

Pour vérifier que les packages critiques sont correctement installés :

```bash
# Activer l'environnement virtuel
source webphantom_env/bin/activate

# Vérifier les packages installés
pip list | grep requests
pip list | grep beautifulsoup4
pip list | grep llama-cpp-python
pip list | grep nltk
```

## Problèmes d'exécution

### Erreur lors de l'exécution d'un scénario YAML

**Problème** : Erreurs lors de l'exécution d'un scénario YAML.

**Solution** : Assurez-vous que toutes les dépendances sont installées et que l'environnement virtuel est activé :

```bash
# Activer l'environnement virtuel
source webphantom_env/bin/activate

# Exécuter le scénario avec une URL cible explicite
python webphantom.py run scripts/advanced_web_test.yaml --target http://example.com
```

### Erreur lors du téléchargement des ressources NLTK

**Problème** : Erreurs lors du téléchargement des ressources NLTK.

**Solution** : Téléchargez manuellement les ressources NLTK nécessaires :

```bash
# Activer l'environnement virtuel
source webphantom_env/bin/activate

# Lancer Python
python

# Dans l'interpréteur Python
import nltk
nltk.download('punkt')
nltk.download('stopwords')
nltk.download('wordnet')
exit()
```

## Autres problèmes

Si vous rencontrez d'autres problèmes, n'hésitez pas à ouvrir une issue sur le dépôt GitHub ou à contacter l'équipe de développement.
