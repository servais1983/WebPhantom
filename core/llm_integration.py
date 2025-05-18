"""
Module d'intégration du modèle LLaMA pour l'analyse de sécurité.
Ce module permet d'utiliser le modèle LLaMA pour analyser les applications web
et identifier des vulnérabilités complexes.
"""

import os
import sys
import logging
import hashlib
import json
import nltk
from pathlib import Path
from tqdm import tqdm
import requests
from llama_cpp import Llama

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("llm_integration")

# Répertoire pour les modèles
HOME_DIR = os.path.expanduser("~")
WEBPHANTOM_DIR = os.path.join(HOME_DIR, ".webphantom")
MODELS_DIR = os.path.join(WEBPHANTOM_DIR, "models")

# URL des modèles
MODEL_URLS = {
    "llama-7b-q4": "https://huggingface.co/TheBloke/LLaMA-7B-GGUF/resolve/main/llama-7b.Q4_K_M.gguf",
    "llama-13b-q4": "https://huggingface.co/TheBloke/LLaMA-13B-GGUF/resolve/main/llama-13b.Q4_K_M.gguf",
}

# Hachage MD5 des modèles pour vérification
MODEL_HASHES = {
    "llama-7b-q4": "a87c04c6fa7f4bea17e68fcfd55e5b2d",
    "llama-13b-q4": "b3dc9a7c1bdcb68b5f6e96b3c8e2f48d",
}

def ensure_models_dir():
    """Assure que le répertoire des modèles existe."""
    os.makedirs(MODELS_DIR, exist_ok=True)
    logger.info(f"Répertoire des modèles: {MODELS_DIR}")

def download_model(model_name):
    """Télécharge un modèle s'il n'existe pas déjà."""
    if model_name not in MODEL_URLS:
        logger.error(f"Modèle {model_name} non disponible")
        return None
    
    model_path = os.path.join(MODELS_DIR, f"{model_name}.gguf")
    if os.path.exists(model_path):
        logger.info(f"Modèle {model_name} déjà téléchargé")
        return model_path
    
    url = MODEL_URLS[model_name]
    logger.info(f"Téléchargement du modèle {model_name} depuis {url}")
    
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        total_size = int(response.headers.get('content-length', 0))
        block_size = 1024  # 1 Kibibyte
        progress_bar = tqdm(total=total_size, unit='iB', unit_scale=True)
        
        with open(model_path, 'wb') as f:
            for data in response.iter_content(block_size):
                progress_bar.update(len(data))
                f.write(data)
        
        progress_bar.close()
        
        if total_size != 0 and progress_bar.n != total_size:
            logger.error("Erreur lors du téléchargement du modèle")
            return None
        
        logger.info(f"Modèle {model_name} téléchargé avec succès")
        return model_path
    
    except Exception as e:
        logger.error(f"Erreur lors du téléchargement du modèle: {e}")
        return None

def verify_model_integrity(model_path, expected_hash):
    """Vérifie l'intégrité d'un modèle en comparant son hash MD5."""
    logger.info(f"Vérification de l'intégrité du modèle {os.path.basename(model_path)}...")
    
    if not os.path.exists(model_path):
        logger.error(f"Le fichier {model_path} n'existe pas")
        return False
    
    md5_hash = hashlib.md5()
    with open(model_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
    
    file_hash = md5_hash.hexdigest()
    
    if file_hash == expected_hash:
        logger.info(f"Intégrité du modèle vérifiée")
        return True
    else:
        logger.warning(f"Intégrité du modèle non vérifiée. Hash attendu: {expected_hash}, hash obtenu: {file_hash}")
        return False

def load_model(model_name="llama-7b-q4", n_ctx=2048, n_gpu_layers=0):
    """Charge un modèle LLaMA."""
    ensure_models_dir()
    
    model_path = os.path.join(MODELS_DIR, f"{model_name}.gguf")
    if not os.path.exists(model_path):
        model_path = download_model(model_name)
        if not model_path:
            logger.error(f"Impossible de charger le modèle {model_name}")
            return None
    
    if model_name in MODEL_HASHES:
        if not verify_model_integrity(model_path, MODEL_HASHES[model_name]):
            logger.warning("L'intégrité du modèle n'a pas pu être vérifiée, mais le chargement va continuer")
    
    try:
        logger.info(f"Chargement du modèle {model_name}...")
        model = Llama(
            model_path=model_path,
            n_ctx=n_ctx,
            n_gpu_layers=n_gpu_layers,
            verbose=False
        )
        logger.info(f"Modèle {model_name} chargé avec succès")
        return model
    
    except Exception as e:
        logger.error(f"Erreur lors du chargement du modèle: {e}")
        return None

def initialize_nltk():
    """Initialise NLTK et télécharge les ressources nécessaires."""
    nltk_data_dir = os.path.join(WEBPHANTOM_DIR, "nltk_data")
    os.makedirs(nltk_data_dir, exist_ok=True)
    nltk.data.path.append(nltk_data_dir)
    
    try:
        # Télécharger les ressources NLTK nécessaires
        nltk.download('punkt', download_dir=nltk_data_dir)
        nltk.download('stopwords', download_dir=nltk_data_dir)
        nltk.download('wordnet', download_dir=nltk_data_dir)
        logger.info("Ressources NLTK téléchargées avec succès")
        return True
    except Exception as e:
        logger.error(f"Erreur lors du téléchargement des ressources NLTK: {e}")
        return False

def preprocess_text(text):
    """Prétraite le texte pour l'analyse."""
    # Utiliser NLTK pour tokenizer et nettoyer le texte
    from nltk.tokenize import word_tokenize
    from nltk.corpus import stopwords
    
    try:
        # Tokenization
        tokens = word_tokenize(text.lower())
        
        # Suppression des stop words
        stop_words = set(stopwords.words('english'))
        filtered_tokens = [w for w in tokens if w not in stop_words]
        
        return " ".join(filtered_tokens)
    except Exception as e:
        logger.error(f"Erreur lors du prétraitement du texte: {e}")
        return text

def analyze_web_content(model, url, html_content, headers=None, response_time=None):
    """Analyse le contenu d'une page web pour détecter des vulnérabilités."""
    if not model:
        logger.error("Modèle non chargé")
        return []
    
    # Prétraiter le contenu HTML
    processed_content = preprocess_text(html_content[:10000])  # Limiter la taille pour éviter les dépassements de contexte
    
    # Construire le prompt pour le modèle
    prompt = f"""
    Analyze the following web page for security vulnerabilities:
    
    URL: {url}
    
    HTML Content (excerpt):
    {processed_content}
    
    Headers:
    {json.dumps(headers) if headers else 'Not provided'}
    
    Response Time: {response_time if response_time else 'Not provided'}
    
    Identify potential security vulnerabilities including but not limited to:
    - XSS (Cross-Site Scripting)
    - SQL Injection
    - CSRF (Cross-Site Request Forgery)
    - SSRF (Server-Side Request Forgery)
    - XXE (XML External Entity)
    - Open Redirects
    - Insecure Deserialization
    - Security Misconfigurations
    
    For each vulnerability, provide:
    1. Type of vulnerability
    2. Evidence from the content
    3. Severity level (Low, Medium, High, Critical)
    4. Potential impact
    5. Remediation suggestions
    
    Format your response as a JSON array of vulnerability objects.
    """
    
    try:
        logger.info(f"Analyse du contenu de {url} avec LLaMA...")
        
        # Générer la réponse du modèle
        response = model.create_completion(
            prompt,
            max_tokens=2048,
            temperature=0.1,
            top_p=0.9,
            stop=["</s>", "\n\n\n"],
            echo=False
        )
        
        # Extraire et parser la réponse
        response_text = response["choices"][0]["text"].strip()
        
        # Tenter de parser la réponse comme JSON
        try:
            # Trouver le début et la fin du JSON dans la réponse
            start_idx = response_text.find('[')
            end_idx = response_text.rfind(']') + 1
            
            if start_idx >= 0 and end_idx > start_idx:
                json_str = response_text[start_idx:end_idx]
                vulnerabilities = json.loads(json_str)
                logger.info(f"Analyse terminée. {len(vulnerabilities)} vulnérabilités potentielles détectées.")
                return vulnerabilities
            else:
                logger.warning("Impossible de trouver un tableau JSON dans la réponse")
                return []
        
        except json.JSONDecodeError:
            logger.warning("Impossible de parser la réponse comme JSON")
            
            # Tenter une extraction manuelle des vulnérabilités
            vulnerabilities = []
            lines = response_text.split('\n')
            current_vuln = {}
            
            for line in lines:
                if "Type of vulnerability:" in line:
                    if current_vuln and "type" in current_vuln:
                        vulnerabilities.append(current_vuln)
                    current_vuln = {"type": line.split(":", 1)[1].strip()}
                elif "Evidence:" in line:
                    current_vuln["evidence"] = line.split(":", 1)[1].strip()
                elif "Severity:" in line:
                    current_vuln["severity"] = line.split(":", 1)[1].strip()
                elif "Impact:" in line:
                    current_vuln["impact"] = line.split(":", 1)[1].strip()
                elif "Remediation:" in line:
                    current_vuln["remediation"] = line.split(":", 1)[1].strip()
            
            if current_vuln and "type" in current_vuln:
                vulnerabilities.append(current_vuln)
            
            logger.info(f"Analyse terminée. {len(vulnerabilities)} vulnérabilités potentielles extraites manuellement.")
            return vulnerabilities
    
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse du contenu: {e}")
        return []

def run(url, options=None):
    """Point d'entrée principal pour l'analyse IA."""
    if not options:
        options = {}
    
    # Initialiser NLTK
    initialize_nltk()
    
    # Charger le modèle
    model_name = options.get("model", "llama-7b-q4")
    n_ctx = options.get("context_size", 2048)
    n_gpu_layers = options.get("gpu_layers", 0)
    
    model = load_model(model_name, n_ctx, n_gpu_layers)
    if not model:
        logger.error("Impossible de charger le modèle LLaMA")
        print("Erreur: Impossible de charger le modèle LLaMA")
        return
    
    # Récupérer le contenu de la page
    try:
        import requests
        from time import time
        
        start_time = time()
        response = requests.get(url, headers={
            "User-Agent": "WebPhantom Security Scanner"
        })
        response_time = time() - start_time
        
        html_content = response.text
        headers = dict(response.headers)
        
        # Analyser le contenu
        vulnerabilities = analyze_web_content(model, url, html_content, headers, response_time)
        
        # Afficher les résultats
        if vulnerabilities:
            print(f"\n[+] Analyse IA avec LLaMA terminée. {len(vulnerabilities)} vulnérabilités potentielles détectées:")
            for i, vuln in enumerate(vulnerabilities, 1):
                vuln_type = vuln.get("type", "Inconnue")
                severity = vuln.get("severity", "Inconnue")
                print(f"\n{i}. Type: {vuln_type} (Sévérité: {severity})")
                
                if "evidence" in vuln:
                    print(f"   Evidence: {vuln['evidence']}")
                
                if "impact" in vuln:
                    print(f"   Impact: {vuln['impact']}")
                
                if "remediation" in vuln:
                    print(f"   Remédiation: {vuln['remediation']}")
        else:
            print("\n[+] Analyse IA avec LLaMA terminée. Aucune vulnérabilité potentielle détectée.")
        
        return vulnerabilities
    
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse: {e}")
        print(f"Erreur: {e}")
        return []

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python llm_integration.py <url>")
        sys.exit(1)
    
    url = sys.argv[1]
    run(url)
