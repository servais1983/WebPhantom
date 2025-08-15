"""
LLaMA model integration for security analysis.
Uses a local LLM to analyze web applications and identify complex vulnerabilities.
Prefers Ollama API; falls back to llama.cpp if needed.
"""

import os
import sys
import logging
import hashlib
import json
try:
    import nltk
except Exception:
    nltk = None
from pathlib import Path
from tqdm import tqdm
import requests
import importlib
try:
    Llama = importlib.import_module("llama_cpp").Llama  # type: ignore[attr-defined]
except Exception:
    Llama = None

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("llm_integration")

# Models directory
HOME_DIR = os.path.expanduser("~")
WEBPHANTOM_DIR = os.path.join(HOME_DIR, ".webphantom")
MODELS_DIR = os.path.join(WEBPHANTOM_DIR, "models")

# Model URLs (for local llama.cpp fallback)
MODEL_URLS = {
    "llama-7b-q4": "https://huggingface.co/TheBloke/LLaMA-7B-GGUF/resolve/main/llama-7b.Q4_K_M.gguf",
    "llama-13b-q4": "https://huggingface.co/TheBloke/LLaMA-13B-GGUF/resolve/main/llama-13b.Q4_K_M.gguf",
}

# MD5 hashes for integrity verification
MODEL_HASHES = {
    "llama-7b-q4": "a87c04c6fa7f4bea17e68fcfd55e5b2d",
    "llama-13b-q4": "b3dc9a7c1bdcb68b5f6e96b3c8e2f48d",
}

def ensure_models_dir():
    """Ensure that the models directory exists."""
    os.makedirs(MODELS_DIR, exist_ok=True)
    logger.info(f"Répertoire des modèles: {MODELS_DIR}")

def download_model(model_name):
    """Download a model if it does not already exist."""
    if model_name not in MODEL_URLS:
        logger.error(f"Model {model_name} not available")
        return None
    
    model_path = os.path.join(MODELS_DIR, f"{model_name}.gguf")
    if os.path.exists(model_path):
        logger.info(f"Model {model_name} already downloaded")
        return model_path
    
    url = MODEL_URLS[model_name]
    logger.info(f"Downloading model {model_name} from {url}")
    
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
            logger.error("Error while downloading model")
            return None
        
        logger.info(f"Model {model_name} downloaded successfully")
        return model_path
    
    except Exception as e:
        logger.error(f"Error while downloading model: {e}")
        return None

def verify_model_integrity(model_path, expected_hash):
    """Verify model integrity by comparing its MD5 hash."""
    logger.info(f"Vérification de l'intégrité du modèle {os.path.basename(model_path)}...")
    
    if not os.path.exists(model_path):
        logger.error(f"File does not exist: {model_path}")
        return False
    
    md5_hash = hashlib.md5()
    with open(model_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
    
    file_hash = md5_hash.hexdigest()
    
    if file_hash == expected_hash:
        logger.info(f"Model integrity verified")
        return True
    else:
        logger.warning(f"Model integrity not verified. Expected: {expected_hash}, got: {file_hash}")
        return False

def load_model(model_name="llama-7b-q4", n_ctx=2048, n_gpu_layers=0):
    """Load a LLaMA model via llama.cpp (fallback if Ollama is unavailable)."""
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
        if Llama is None:
            logger.error("llama-cpp-python unavailable. Cannot load a GGUF model.")
            return None
        model = Llama(
            model_path=model_path,
            n_ctx=n_ctx,
            n_gpu_layers=n_gpu_layers,
            verbose=False
        )
        logger.info(f"Model {model_name} loaded successfully")
        return model
    
    except Exception as e:
        logger.error(f"Error while loading model: {e}")
        return None

def initialize_nltk():
    """Initialize NLTK and download required resources."""
    if nltk is None:
        logger.warning("NLTK not available. Preprocessing will be limited.")
        return False
    nltk_data_dir = os.path.join(WEBPHANTOM_DIR, "nltk_data")
    os.makedirs(nltk_data_dir, exist_ok=True)
    nltk.data.path.append(nltk_data_dir)
    
    try:
        # Download NLTK resources
        nltk.download('punkt', download_dir=nltk_data_dir)
        nltk.download('stopwords', download_dir=nltk_data_dir)
        nltk.download('wordnet', download_dir=nltk_data_dir)
        logger.info("NLTK resources downloaded successfully")
        return True
    except Exception as e:
        logger.error(f"Error while downloading NLTK resources: {e}")
        return False

def preprocess_text(text):
    """Preprocess text for analysis."""
    if nltk is None:
        return text.lower()
    try:
        # Use NLTK to tokenize and clean the text
        from nltk.tokenize import word_tokenize
        from nltk.corpus import stopwords
        
        # Tokenization
        tokens = word_tokenize(text.lower())
        
        # Remove stop words
        stop_words = set(stopwords.words('english'))
        filtered_tokens = [w for w in tokens if w not in stop_words]
        
        return " ".join(filtered_tokens)
    except Exception as e:
        logger.error(f"Error during text preprocessing: {e}")
        return text

def analyze_web_content(model, url, html_content, headers=None, response_time=None):
    """Analyze a web page content to detect vulnerabilities."""
    if not model:
        logger.error("Model not loaded")
        return []
    
    # Preprocess HTML content
    processed_content = preprocess_text(html_content[:10000])  # Limiter la taille pour éviter les dépassements de contexte
    
    # Build model prompt
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
        logger.info(f"Analyzing content from {url} with LLaMA...")
        
        # Generate model response
        response = model.create_completion(
            prompt,
            max_tokens=2048,
            temperature=0.1,
            top_p=0.9,
            stop=["</s>", "\n\n\n"],
            echo=False
        )
        
        # Extract and parse response
        response_text = response["choices"][0]["text"].strip()
        
        # Tenter de parser la réponse comme JSON
        try:
            # Find JSON boundaries in the response
            start_idx = response_text.find('[')
            end_idx = response_text.rfind(']') + 1
            
            if start_idx >= 0 and end_idx > start_idx:
                json_str = response_text[start_idx:end_idx]
                vulnerabilities = json.loads(json_str)
                logger.info(f"Analysis complete. {len(vulnerabilities)} potential vulnerabilities detected.")
                return vulnerabilities
            else:
                logger.warning("Could not find a JSON array in the response")
                return []
        
        except json.JSONDecodeError:
            logger.warning("Could not parse response as JSON")
            
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
            
            logger.info(f"Analysis complete. {len(vulnerabilities)} potential vulnerabilities extracted manually.")
            return vulnerabilities
    
    except Exception as e:
        logger.error(f"Error while analyzing content: {e}")
        return []

def _ollama_is_running(base_url="http://localhost:11434"):
    try:
        r = requests.get(f"{base_url}/api/tags", timeout=2)
        return r.status_code == 200
    except Exception:
        return False


def _ollama_generate(prompt, model="llama3.1", base_url="http://localhost:11434", max_tokens=2048, temperature=0.1, stop=None):
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "num_predict": max_tokens,
            "temperature": temperature,
        },
    }
    if stop:
        payload["stop"] = stop
    r = requests.post(f"{base_url}/api/generate", json=payload, timeout=120)
    r.raise_for_status()
    data = r.json()
    # Ollama returns the text in 'response'
    return data.get("response", "")


def _build_prompt(url, html_content, headers=None, response_time=None):
    processed_content = preprocess_text(html_content[:10000])
    return f"""
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


def _parse_vulns_from_text(response_text):
    try:
        start_idx = response_text.find('[')
        end_idx = response_text.rfind(']') + 1
        if start_idx >= 0 and end_idx > start_idx:
            json_str = response_text[start_idx:end_idx]
            return json.loads(json_str)
    except Exception:
        pass

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
    return vulnerabilities


def run(url, options=None):
    """Main entry point for AI-assisted analysis."""
    if not options:
        options = {}

    # Initialize NLTK
    initialize_nltk()

    provider = options.get("provider", "ollama")
    ollama_url = options.get("ollama_url", "http://localhost:11434")
    ollama_model = options.get("model", "llama3.1")

    # Fetch page content
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
        
        # Build prompt
        prompt = _build_prompt(url, html_content, headers, response_time)

        vulnerabilities = []

        if provider == "ollama" and _ollama_is_running(ollama_url):
            logger.info(f"Analyzing content from {url} with Ollama ({ollama_model})...")
            try:
                response_text = _ollama_generate(
                    prompt,
                    model=ollama_model,
                    base_url=ollama_url,
                    max_tokens=options.get("max_tokens", 2048),
                    temperature=options.get("temperature", 0.1),
                    stop=["</s>", "\n\n\n"],
                )
                vulnerabilities = _parse_vulns_from_text(response_text)
                logger.info(f"Analysis via Ollama complete. {len(vulnerabilities)} potential vulnerabilities detected.")
            except Exception as e:
                logger.error(f"Ollama error: {e}. Falling back to local llama.cpp…")
        
        if not vulnerabilities:
            # Fallback: local llama.cpp if possible
            model_name = options.get("local_model", "llama-7b-q4")
            n_ctx = options.get("context_size", 2048)
            n_gpu_layers = options.get("gpu_layers", 0)
            model = load_model(model_name, n_ctx, n_gpu_layers)
            if not model:
                logger.error("Unable to load LLaMA model (fallback)")
                print("Error: Unable to load LLaMA model")
                return []
            vulnerabilities = analyze_web_content(model, url, html_content, headers, response_time)
        
        # Print results
        if vulnerabilities:
            print(f"\n[+] AI analysis complete. {len(vulnerabilities)} potential vulnerabilities detected:")
            for i, vuln in enumerate(vulnerabilities, 1):
                vuln_type = vuln.get("type", "Inconnue")
                severity = vuln.get("severity", "Inconnue")
                print(f"\n{i}. Type: {vuln_type} (Severity: {severity})")
                
                if "evidence" in vuln:
                    print(f"   Evidence: {vuln['evidence']}")
                
                if "impact" in vuln:
                    print(f"   Impact: {vuln['impact']}")
                
                if "remediation" in vuln:
                    print(f"   Remediation: {vuln['remediation']}")
        else:
            print("\n[+] AI analysis complete. No potential vulnerabilities detected.")
        
        return vulnerabilities
    
    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        print(f"Error: {e}")
        return []

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python llm_integration.py <url>")
        sys.exit(1)
    
    url = sys.argv[1]
    run(url)
