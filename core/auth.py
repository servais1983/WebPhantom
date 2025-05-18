"""
Module de gestion des utilisateurs et d'authentification pour WebPhantom.
Supporte Basic Auth, Forms et JWT.
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

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Répertoire pour stocker les données utilisateurs
USER_DIR = os.path.expanduser("~/.webphantom/users")
os.makedirs(USER_DIR, exist_ok=True)
USER_DB = os.path.join(USER_DIR, "users.json")

# Clé secrète pour JWT
JWT_SECRET = os.environ.get("WEBPHANTOM_JWT_SECRET", "webphantom_secret_key")

# Initialiser la base de données utilisateurs si elle n'existe pas
if not os.path.exists(USER_DB):
    with open(USER_DB, "w") as f:
        json.dump({"users": []}, f)

def register(username, email, role="user", password=None):
    """
    Enregistre un nouvel utilisateur.
    
    Args:
        username (str): Nom d'utilisateur
        email (str): Adresse email
        role (str, optional): Rôle de l'utilisateur (admin, user). Par défaut "user".
        password (str, optional): Mot de passe. Si non fourni, un mot de passe aléatoire est généré.
        
    Returns:
        dict: Informations sur l'utilisateur créé
    """
    # Charger la base de données utilisateurs
    with open(USER_DB, "r") as f:
        db = json.load(f)
    
    # Vérifier si l'utilisateur existe déjà
    for user in db["users"]:
        if user["username"] == username or user["email"] == email:
            logger.warning(f"L'utilisateur {username} ou l'email {email} existe déjà")
            return {"success": False, "error": "L'utilisateur ou l'email existe déjà"}
    
    # Générer un mot de passe aléatoire si non fourni
    if not password:
        import random
        import string
        password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))
        logger.info(f"Mot de passe généré pour {username}: {password}")
    
    # Hacher le mot de passe
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # Créer l'utilisateur
    user = {
        "username": username,
        "email": email,
        "role": role,
        "password_hash": hashed_password.decode('utf-8'),
        "created_at": datetime.datetime.now().isoformat()
    }
    
    # Ajouter l'utilisateur à la base de données
    db["users"].append(user)
    
    # Sauvegarder la base de données
    with open(USER_DB, "w") as f:
        json.dump(db, f, indent=2)
    
    logger.info(f"Utilisateur {username} enregistré avec succès")
    return {
        "success": True, 
        "username": username, 
        "email": email, 
        "role": role,
        "password": password if not password else "[MASQUÉ]"
    }

def authenticate(auth_type, username, password, url=None):
    """
    Authentifie un utilisateur avec différentes méthodes.
    
    Args:
        auth_type (str): Type d'authentification (basic, form, jwt)
        username (str): Nom d'utilisateur
        password (str): Mot de passe
        url (str, optional): URL pour l'authentification par formulaire
        
    Returns:
        dict: Résultat de l'authentification et token JWT si applicable
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
    Authentification Basic.
    
    Args:
        username (str): Nom d'utilisateur
        password (str): Mot de passe
        url (str): URL à tester avec Basic Auth
        
    Returns:
        dict: Résultat de l'authentification
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
    Authentification par formulaire.
    
    Args:
        username (str): Nom d'utilisateur
        password (str): Mot de passe
        url (str): URL du formulaire d'authentification
        
    Returns:
        dict: Résultat de l'authentification
    """
    if not url:
        # Authentification locale
        return _local_auth(username, password)
    
    # Déterminer les champs du formulaire (simple heuristique)
    username_field = "username"
    password_field = "password"
    
    # Tenter de détecter les champs du formulaire
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
    
    # Préparer les données du formulaire
    data = {
        username_field: username,
        password_field: password
    }
    
    # Envoyer la requête
    try:
        session = requests.Session()
        response = session.post(url, data=data, allow_redirects=True)
        
        # Vérifier si l'authentification a réussi (heuristique simple)
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
    Authentification JWT.
    
    Args:
        username (str): Nom d'utilisateur
        password (str): Mot de passe
        
    Returns:
        dict: Résultat de l'authentification et token JWT
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
        
        logger.info(f"Token JWT généré pour {username}")
        return {
            "success": True,
            "token": token,
            "expires": payload["exp"].isoformat(),
            "role": auth_result["role"]
        }
    except Exception as e:
        logger.error(f"Erreur lors de la génération du token JWT: {str(e)}")
        return {"success": False, "error": str(e)}

def verify_jwt(token):
    """
    Vérifie un token JWT.
    
    Args:
        token (str): Token JWT à vérifier
        
    Returns:
        dict: Informations sur le token si valide
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        logger.info(f"Token JWT valide pour {payload['sub']}")
        return {"success": True, "username": payload["sub"], "role": payload["role"]}
    except jwt.ExpiredSignatureError:
        logger.warning("Token JWT expiré")
        return {"success": False, "error": "Token expiré"}
    except jwt.InvalidTokenError:
        logger.warning("Token JWT invalide")
        return {"success": False, "error": "Token invalide"}

def _local_auth(username, password):
    """
    Authentification locale avec la base de données utilisateurs.
    
    Args:
        username (str): Nom d'utilisateur
        password (str): Mot de passe
        
    Returns:
        dict: Résultat de l'authentification
    """
    # Charger la base de données utilisateurs
    with open(USER_DB, "r") as f:
        db = json.load(f)
    
    # Rechercher l'utilisateur
    for user in db["users"]:
        if user["username"] == username:
            # Vérifier le mot de passe
            if bcrypt.checkpw(password.encode('utf-8'), user["password_hash"].encode('utf-8')):
                logger.info(f"Authentification locale réussie pour {username}")
                return {"success": True, "username": username, "role": user["role"]}
            else:
                logger.warning(f"Mot de passe incorrect pour {username}")
                return {"success": False, "error": "Mot de passe incorrect"}
    
    logger.warning(f"Utilisateur {username} non trouvé")
    return {"success": False, "error": "Utilisateur non trouvé"}

def run(url, options=None):
    """
    Fonction principale pour l'exécution du module d'authentification.
    
    Args:
        url (str): URL cible
        options (dict, optional): Options supplémentaires
        
    Returns:
        dict: Résultat de l'opération
    """
    if not options:
        options = {}
    
    auth_type = options.get("type", "basic")
    username = options.get("username", "admin")
    password = options.get("password", "password")
    
    logger.info(f"Test d'authentification {auth_type} sur {url}")
    result = authenticate(auth_type, username, password, url)
    
    if result["success"]:
        print(f"[+] Authentification {auth_type} réussie pour {username}")
    else:
        print(f"[-] Échec de l'authentification {auth_type} pour {username}")
    
    return result
