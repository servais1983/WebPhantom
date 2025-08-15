"""
User and authentication management for WebPhantom.
Supports Basic Auth, form auth and JWT.
"""

import os
import json
import bcrypt
import jwt
import datetime
import requests
from urllib.parse import urlparse
import base64
import logging
from typing import Optional

# Logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Directory to store user data
USER_DIR = os.path.expanduser("~/.webphantom/users")
os.makedirs(USER_DIR, exist_ok=True)
USER_DB = os.path.join(USER_DIR, "users.json")

# JWT secret
JWT_SECRET = os.environ.get("WEBPHANTOM_JWT_SECRET", "webphantom_secret_key")

# Initialiser la base de données utilisateurs si elle n'existe pas
if not os.path.exists(USER_DB):
    with open(USER_DB, "w") as f:
        json.dump({"users": []}, f)

def register(username, email, role="user", password=None):
    """
    Register a new user.
    
    Args:
        username (str): Username
        email (str): Email
        role (str, optional): User role (admin, user). Defaults to "user".
        password (str, optional): Password. If not provided, a random one is generated.
        
    Returns:
        dict: Created user info
    """
    # Charger la base de données utilisateurs
    with open(USER_DB, "r") as f:
        db = json.load(f)
    
    # Check if user already exists
    for user in db["users"]:
        if user["username"] == username or user["email"] == email:
            logger.warning(f"L'utilisateur {username} ou l'email {email} existe déjà")
            return {"success": False, "error": "L'utilisateur ou l'email existe déjà"}
    
    # Generate random password if not provided
    if not password:
        import random
        import string
        password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))
        logger.info(f"Mot de passe généré pour {username}: {password}")
    
    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # Créer l'utilisateur
    user = {
        "username": username,
        "email": email,
        "role": role,
        "password_hash": hashed_password.decode('utf-8'),
        "created_at": datetime.datetime.now().isoformat()
    }
    
    # Add user to DB
    db["users"].append(user)
    
    # Sauvegarder la base de données
    with open(USER_DB, "w") as f:
        json.dump(db, f, indent=2)
    
    logger.info(f"User {username} registered successfully")
    return {
        "success": True, 
        "username": username, 
        "email": email, 
        "role": role,
        "password": password if not password else "[MASQUÉ]"
    }

def authenticate(auth_type, username, password, url=None):
    """
    Authenticate with different methods.
    
    Args:
        auth_type (str): Auth type (basic, form, jwt)
        username (str): Username
        password (str): Password
        url (str, optional): URL for form-based auth
        
    Returns:
        dict: Result and JWT token if applicable
    """
    if auth_type == "basic":
        return basic_auth(username, password, url)
    elif auth_type == "form":
        return form_auth(username, password, url)
    elif auth_type == "jwt":
        return jwt_auth(username, password)
    else:
        logger.error(f"Type d'authentification non supporté: {auth_type}")
        return {"success": False, "error": f"Type d'authentification non supporté: {auth_type}"}

def basic_auth(username, password, url):
    """
    Basic authentication.
    """
    if not url:
        # Authentification locale
        return _local_auth(username, password)
    
    # Authentification distante
    auth = (username, password)
    try:
        response = requests.get(url, auth=auth)
        if response.status_code == 200:
            logger.info(f"Authentification Basic réussie pour {username} sur {url}")
            return {"success": True, "status_code": response.status_code}
        else:
            logger.warning(f"Échec de l'authentification Basic pour {username} sur {url}")
            return {"success": False, "status_code": response.status_code}
    except Exception as e:
        logger.error(f"Erreur lors de l'authentification Basic: {str(e)}")
        return {"success": False, "error": str(e)}

def form_auth(username, password, url):
    """
    Form authentication.
    """
    if not url:
        # Authentification locale
        return _local_auth(username, password)
    
    # Guess form fields (basic heuristic)
    username_field = "username"
    password_field = "password"
    
    # Try to detect form fields
    try:
        response = requests.get(url)
        if "user" in response.text.lower() and "name" in response.text.lower():
            username_field = "username"
        elif "email" in response.text.lower():
            username_field = "email"
        
        if "pass" in response.text.lower():
            password_field = "password"
    except Exception:
        pass
    
    # Prepare form data
    data = {
        username_field: username,
        password_field: password
    }
    
    # Send request
    try:
        session = requests.Session()
        response = session.post(url, data=data, allow_redirects=True)
        
        # Check if authentication succeeded (simple heuristic)
        success = response.status_code == 200 and "error" not in response.text.lower() and "invalid" not in response.text.lower()
        
        if success:
            logger.info(f"Authentification par formulaire réussie pour {username} sur {url}")
            return {"success": True, "status_code": response.status_code, "cookies": dict(session.cookies)}
        else:
            logger.warning(f"Échec de l'authentification par formulaire pour {username} sur {url}")
            return {"success": False, "status_code": response.status_code}
    except Exception as e:
        logger.error(f"Erreur lors de l'authentification par formulaire: {str(e)}")
        return {"success": False, "error": str(e)}

def jwt_auth(username, password):
    """
    JWT authentication.
    """
    # Authentification locale
    auth_result = _local_auth(username, password)
    if not auth_result["success"]:
        return auth_result
    
    # Générer un token JWT
    try:
        payload = {
            "sub": username,
            "role": auth_result["role"],
            "iat": datetime.datetime.utcnow(),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
        
        logger.info(f"JWT token generated for {username}")
        return {
            "success": True,
            "token": token,
            "expires": payload["exp"].isoformat(),
            "role": auth_result["role"]
        }
    except Exception as e:
        logger.error(f"Error while generating JWT: {str(e)}")
        return {"success": False, "error": str(e)}

def verify_jwt(token):
    """
    Verify a JWT token.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        logger.info(f"JWT token valid for {payload['sub']}")
        return {"success": True, "username": payload["sub"], "role": payload["role"]}
    except jwt.ExpiredSignatureError:
        logger.warning("JWT token expired")
        return {"success": False, "error": "Token expiré"}
    except jwt.InvalidTokenError:
        logger.warning("JWT token invalid")
        return {"success": False, "error": "Token invalide"}

def _local_auth(username, password):
    """
    Local authentication against the JSON users database.
    """
    # Charger la base de données utilisateurs
    with open(USER_DB, "r") as f:
        db = json.load(f)
    
    # Rechercher l'utilisateur
    for user in db["users"]:
        if user["username"] == username:
            # Vérifier le mot de passe
            if bcrypt.checkpw(password.encode('utf-8'), user["password_hash"].encode('utf-8')):
                logger.info(f"Local authentication succeeded for {username}")
                return {"success": True, "username": username, "role": user["role"]}
            else:
                logger.warning(f"Incorrect password for {username}")
                return {"success": False, "error": "Mot de passe incorrect"}
    
    logger.warning(f"User {username} not found")
    return {"success": False, "error": "Utilisateur non trouvé"}

def run(url, options=None):
    """
    Main entry point for the authentication module.
    """
    if not options:
        options = {}
    
    action = options.get("action")
    if action == "setup":
        cfg = options
        create_user = (cfg.get("create_user") or {})
        username = create_user.get("username", "pentester")
        email = create_user.get("email", f"{username}@example.com")
        role = create_user.get("role", "pentester")
        password = create_user.get("password", "S3cur3P@ssw0rd!")
        reg = register(username=username, email=email, role=role, password=password)
        if not reg.get("success"):
            print("[-] Échec de la création de l'utilisateur")
            return reg
        print(f"[+] Utilisateur créé: {username}")

        if cfg.get("save_token") and cfg.get("auth_method", "jwt") == "jwt":
            jwt_res = jwt_auth(username, password)
            if jwt_res.get("success"):
                token_file = cfg.get("token_file", "auth_token.txt")
                try:
                    with open(token_file, "w") as f:
                        f.write(jwt_res["token"]) 
                    print(f"[+] Token JWT sauvegardé dans {token_file}")
                except Exception as e:
                    logger.error(f"Erreur lors de l'écriture du token: {str(e)}")
            return jwt_res
        return reg

    # Mode test d'auth classique
    auth_type = options.get("type", "basic")
    username = options.get("username", "admin")
    password = options.get("password", "password")
    logger.info(f"Authentication test {auth_type} on {url}")
    result = authenticate(auth_type, username, password, url)
    if result.get("success"):
        print(f"[+] {auth_type} authentication succeeded for {username}")
    else:
        print(f"[-] {auth_type} authentication failed for {username}")
    return result


class AuthManager:
    """Compatibilité pour les tests hérités attendus.

    Fournit une interface orientée objet pour gérer les utilisateurs dans un fichier JSON.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or USER_DB
        # Si un chemin custom est fourni, l'utiliser (et initialiser si besoin)
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        if not os.path.exists(self.db_path):
            with open(self.db_path, "w") as f:
                json.dump({"users": []}, f)

    def _load(self):
        with open(self.db_path, "r") as f:
            return json.load(f)

    def _save(self, data):
        with open(self.db_path, "w") as f:
            json.dump(data, f, indent=2)

    def register_user(self, username: str, email: str, password: str, role: str = "user"):
        data = self._load()
        for u in data.get("users", []):
            if u["username"] == username or u["email"] == email:
                return None
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        user = {
            "username": username,
            "email": email,
            "role": role,
            "password_hash": hashed_password,
            "created_at": datetime.datetime.now().isoformat(),
        }
        data.setdefault("users", []).append(user)
        self._save(data)
        return type("User", (), user)

    def authenticate(self, username: str, password: str):
        data = self._load()
        for u in data.get("users", []):
            if u["username"] == username and bcrypt.checkpw(password.encode("utf-8"), u["password_hash"].encode("utf-8")):
                return type("User", (), u)
        return None

    def create_jwt_token(self, user) -> str:
        payload = {
            "sub": user.username,
            "role": user.role,
            "iat": datetime.datetime.utcnow(),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24),
        }
        return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    def verify_jwt_token(self, token: str):
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            return type("User", (), {"username": payload["sub"], "role": payload["role"]})
        except Exception:
            return None
