"""
Module d'intégration du modèle LLaMA pour l'analyse de sécurité web.
Ce module permet de charger et d'utiliser le modèle LLaMA pour analyser
les vulnérabilités et les risques de sécurité dans les applications web.
"""

import os
import sys
import requests
import hashlib
from pathlib import Path
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("llm_integration")

# Répertoire pour stocker les modèles
MODELS_DIR = os.path.expanduser("~/.webphantom/models")

# URL et hash du modèle LLaMA par défaut (version légère pour les tests)
DEFAULT_MODEL = {
    "name": "llama-2-7b-chat.Q4_K_M.gguf",
    "url": "https://huggingface.co/TheBloke/Llama-2-7B-Chat-GGUF/resolve/main/llama-2-7b-chat.Q4_K_M.gguf",
    "md5": "e0b99920cf47b94c78d217cd65515e74"
}

def ensure_models_dir():
    """Crée le répertoire des modèles s'il n'existe pas."""
    os.makedirs(MODELS_DIR, exist_ok=True)
    logger.info(f"Répertoire des modèles: {MODELS_DIR}")

def download_model(model_info=DEFAULT_MODEL, force=False):
    """
    Télécharge le modèle LLaMA si nécessaire.
    
    Args:
        model_info: Dictionnaire contenant les informations du modèle
        force: Force le téléchargement même si le fichier existe
        
    Returns:
        Path: Chemin vers le fichier du modèle
    """
    ensure_models_dir()
    model_path = Path(MODELS_DIR) / model_info["name"]
    
    # Vérifier si le modèle existe déjà
    if model_path.exists() and not force:
        logger.info(f"Le modèle {model_info['name']} existe déjà.")
        # Vérifier l'intégrité du fichier
        if verify_model_integrity(model_path, model_info["md5"]):
            logger.info("Vérification de l'intégrité du modèle: OK")
            return model_path
        else:
            logger.warning("Intégrité du modèle compromise, téléchargement à nouveau...")
    
    # Télécharger le modèle
    logger.info(f"Téléchargement du modèle {model_info['name']}...")
    try:
        with requests.get(model_info["url"], stream=True) as r:
            r.raise_for_status()
            total_size = int(r.headers.get('content-length', 0))
            block_size = 8192
            downloaded = 0
            
            with open(model_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=block_size):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        # Afficher la progression
                        progress = int(50 * downloaded / total_size)
                        sys.stdout.write(f"\r[{'=' * progress}{' ' * (50 - progress)}] {downloaded}/{total_size} bytes")
                        sys.stdout.flush()
            
            print()  # Nouvelle ligne après la barre de progression
        
        # Vérifier l'intégrité après téléchargement
        if verify_model_integrity(model_path, model_info["md5"]):
            logger.info("Téléchargement et vérification du modèle: OK")
            return model_path
        else:
            logger.error("Le modèle téléchargé est corrompu.")
            return None
            
    except Exception as e:
        logger.error(f"Erreur lors du téléchargement du modèle: {e}")
        if model_path.exists():
            model_path.unlink()  # Supprimer le fichier partiellement téléchargé
        return None

def verify_model_integrity(model_path, expected_md5):
    """
    Vérifie l'intégrité du modèle en comparant son hash MD5.
    
    Args:
        model_path: Chemin vers le fichier du modèle
        expected_md5: Hash MD5 attendu
        
    Returns:
        bool: True si l'intégrité est vérifiée, False sinon
    """
    logger.info(f"Vérification de l'intégrité du modèle {model_path.name}...")
    md5_hash = hashlib.md5()
    with open(model_path, "rb") as f:
        # Lire le fichier par morceaux pour éviter de charger tout en mémoire
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
    
    file_md5 = md5_hash.hexdigest()
    return file_md5 == expected_md5

def load_llama_model(model_path=None):
    """
    Charge le modèle LLaMA.
    
    Args:
        model_path: Chemin vers le fichier du modèle (optionnel)
        
    Returns:
        object: Instance du modèle LLaMA chargé
    """
    try:
        from llama_cpp import Llama
    except ImportError:
        logger.error("La bibliothèque llama-cpp-python n'est pas installée.")
        logger.info("Installation avec: pip install llama-cpp-python")
        return None
    
    if model_path is None:
        model_path = download_model()
        if model_path is None:
            return None
    
    logger.info(f"Chargement du modèle LLaMA depuis {model_path}...")
    try:
        # Paramètres optimisés pour un bon équilibre performance/mémoire
        model = Llama(
            model_path=str(model_path),
            n_ctx=2048,           # Taille du contexte
            n_batch=512,          # Taille du batch pour l'inférence
            n_gpu_layers=0        # Nombre de couches à décharger sur GPU (0 pour CPU uniquement)
        )
        logger.info("Modèle LLaMA chargé avec succès")
        return model
    except Exception as e:
        logger.error(f"Erreur lors du chargement du modèle LLaMA: {e}")
        return None

def analyze_with_llama(model, url, html_content, headers, forms_data=None):
    """
    Analyse une page web avec le modèle LLaMA pour détecter des vulnérabilités.
    
    Args:
        model: Instance du modèle LLaMA
        url: URL de la page analysée
        html_content: Contenu HTML de la page
        headers: En-têtes HTTP de la réponse
        forms_data: Données des formulaires détectés (optionnel)
        
    Returns:
        dict: Résultats de l'analyse avec les vulnérabilités détectées et recommandations
    """
    if model is None:
        logger.error("Aucun modèle LLaMA n'a été chargé.")
        return {
            "success": False,
            "error": "Modèle LLaMA non disponible",
            "vulnerabilities": [],
            "recommendations": ["Installer llama-cpp-python et télécharger le modèle"]
        }
    
    # Limiter la taille du HTML pour éviter de dépasser le contexte du modèle
    html_sample = html_content[:10000] if len(html_content) > 10000 else html_content
    
    # Construire le prompt pour l'analyse de sécurité
    prompt = f"""
Tu es un expert en sécurité web chargé d'analyser une page web pour détecter des vulnérabilités.

URL: {url}

En-têtes HTTP:
{headers}

Extrait du HTML:
```html
{html_sample}
```

"""
    
    if forms_data:
        prompt += f"""
Formulaires détectés:
{forms_data}
"""
    
    prompt += """
Analyse cette page web et identifie les vulnérabilités potentielles parmi les suivantes:
1. Injections (SQL, NoSQL, OS, LDAP)
2. Cross-Site Scripting (XSS)
3. Broken Authentication
4. Insecure Direct Object References (IDOR)
5. Security Misconfiguration
6. Cross-Site Request Forgery (CSRF)
7. Server-Side Request Forgery (SSRF)
8. XML External Entities (XXE)
9. Insecure Deserialization
10. Using Components with Known Vulnerabilities
11. Insufficient Logging & Monitoring

Pour chaque vulnérabilité identifiée, fournis:
- Une description du problème
- Un niveau de risque (Critique, Élevé, Moyen, Faible)
- Une explication technique
- Des recommandations pour corriger le problème

Format de réponse:
{
  "vulnerabilities": [
    {
      "type": "Type de vulnérabilité",
      "risk_level": "Niveau de risque",
      "description": "Description du problème",
      "technical_details": "Explication technique",
      "recommendations": ["Recommandation 1", "Recommandation 2"]
    }
  ],
  "general_recommendations": ["Recommandation générale 1", "Recommandation générale 2"]
}
"""
    
    try:
        # Générer la réponse avec le modèle LLaMA
        logger.info("Analyse en cours avec LLaMA...")
        response = model.create_completion(
            prompt,
            max_tokens=2048,
            temperature=0.1,
            top_p=0.9,
            stop=["```"],
            echo=False
        )
        
        # Extraire et parser la réponse
        llm_response = response["choices"][0]["text"].strip()
        
        # Tentative de parsing du JSON dans la réponse
        import json
        import re
        
        # Rechercher un objet JSON dans la réponse
        json_match = re.search(r'({[\s\S]*})', llm_response)
        if json_match:
            try:
                result = json.loads(json_match.group(1))
                result["success"] = True
                return result
            except json.JSONDecodeError:
                pass
        
        # Si le parsing JSON échoue, retourner la réponse brute
        return {
            "success": True,
            "raw_analysis": llm_response,
            "vulnerabilities": [],
            "general_recommendations": ["Analyse manuelle requise pour interpréter les résultats"]
        }
        
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse avec LLaMA: {e}")
        return {
            "success": False,
            "error": str(e),
            "vulnerabilities": [],
            "recommendations": ["Réessayer avec un modèle plus petit ou plus de ressources"]
        }

# Fonction principale pour l'analyse
def analyze_security(url, html_content, headers, forms_data=None, custom_model_path=None):
    """
    Fonction principale pour l'analyse de sécurité avec LLaMA.
    
    Args:
        url: URL de la page analysée
        html_content: Contenu HTML de la page
        headers: En-têtes HTTP de la réponse
        forms_data: Données des formulaires détectés (optionnel)
        custom_model_path: Chemin vers un modèle personnalisé (optionnel)
        
    Returns:
        dict: Résultats de l'analyse
    """
    model_path = custom_model_path
    if model_path is None:
        model_path = download_model()
    
    if model_path is None:
        return {
            "success": False,
            "error": "Impossible de télécharger ou de trouver le modèle LLaMA",
            "vulnerabilities": [],
            "recommendations": ["Vérifier la connexion internet", "Vérifier l'espace disque disponible"]
        }
    
    model = load_llama_model(model_path)
    return analyze_with_llama(model, url, html_content, headers, forms_data)
