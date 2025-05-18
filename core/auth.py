"""
Module de gestion des utilisateurs et d'authentification pour WebPhantom.
Ce module permet de gérer les utilisateurs, les rôles et les permissions,
ainsi que l'authentification via différentes méthodes (Basic, Forms, JWT).
"""

import os
import json
import time
import uuid
import logging
import sqlite3
import hashlib
import secrets
import datetime
from pathlib import Path
import jwt
import bcrypt
from functools import wraps

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("auth")

# Répertoire pour stocker la base de données
DATA_DIR = os.path.expanduser("~/.webphantom/data")
os.makedirs(DATA_DIR, exist_ok=True)

# Chemin de la base de données
DB_PATH = os.path.join(DATA_DIR, "users.db")

# Clé secrète pour JWT
JWT_SECRET = os.environ.get("WEBPHANTOM_JWT_SECRET", secrets.token_hex(32))

# Durée de validité du token JWT (en secondes)
JWT_EXPIRATION = 86400  # 24 heures

# Rôles disponibles
ROLES = {
    "admin": "Administrateur avec accès complet",
    "pentester": "Utilisateur pouvant effectuer des scans et générer des rapports",
    "viewer": "Utilisateur pouvant uniquement consulter les rapports"
}

class User:
    """Classe représentant un utilisateur."""
    
    def __init__(self, id=None, username=None, email=None, password_hash=None, role="viewer", created_at=None, last_login=None):
        self.id = id or str(uuid.uuid4())
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.role = role
        self.created_at = created_at or datetime.datetime.now().isoformat()
        self.last_login = last_login
    
    def to_dict(self):
        """Convertit l'utilisateur en dictionnaire."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "created_at": self.created_at,
            "last_login": self.last_login
        }
    
    @staticmethod
    def from_dict(data):
        """Crée un utilisateur à partir d'un dictionnaire."""
        return User(
            id=data.get("id"),
            username=data.get("username"),
            email=data.get("email"),
            password_hash=data.get("password_hash"),
            role=data.get("role", "viewer"),
            created_at=data.get("created_at"),
            last_login=data.get("last_login")
        )

class AuthManager:
    """Gestionnaire d'authentification et d'utilisateurs."""
    
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialise la base de données."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Créer la table des utilisateurs si elle n'existe pas
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_login TEXT
        )
        ''')
        
        # Créer la table des sessions si elle n'existe pas
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        # Créer un utilisateur admin par défaut si aucun utilisateur n'existe
        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]
        
        if count == 0:
            admin_password = secrets.token_urlsafe(12)
            admin_password_hash = bcrypt.hashpw(admin_password.encode(), bcrypt.gensalt()).decode()
            
            cursor.execute(
                "INSERT INTO users (id, username, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    str(uuid.uuid4()),
                    "admin",
                    "admin@webphantom.local",
                    admin_password_hash,
                    "admin",
                    datetime.datetime.now().isoformat()
                )
            )
            
            logger.info(f"Utilisateur admin créé avec le mot de passe: {admin_password}")
            logger.info("Veuillez changer ce mot de passe dès que possible!")
        
        conn.commit()
        conn.close()
    
    def register_user(self, username, email, password, role="viewer"):
        """
        Enregistre un nouvel utilisateur.
        
        Args:
            username: Nom d'utilisateur
            email: Adresse e-mail
            password: Mot de passe en clair
            role: Rôle de l'utilisateur
            
        Returns:
            User: Utilisateur créé ou None en cas d'erreur
        """
        try:
            # Vérifier que le rôle est valide
            if role not in ROLES:
                logger.error(f"Rôle invalide: {role}")
                return None
            
            # Hacher le mot de passe
            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            
            # Créer l'utilisateur
            user = User(
                username=username,
                email=email,
                password_hash=password_hash,
                role=role
            )
            
            # Enregistrer l'utilisateur dans la base de données
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                "INSERT INTO users (id, username, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    user.id,
                    user.username,
                    user.email,
                    user.password_hash,
                    user.role,
                    user.created_at
                )
            )
            
            conn.commit()
            conn.close()
            
            logger.info(f"Utilisateur {username} créé avec succès")
            return user
        
        except sqlite3.IntegrityError as e:
            logger.error(f"Erreur d'intégrité lors de la création de l'utilisateur: {e}")
            return None
        
        except Exception as e:
            logger.error(f"Erreur lors de la création de l'utilisateur: {e}")
            return None
    
    def authenticate(self, username, password):
        """
        Authentifie un utilisateur.
        
        Args:
            username: Nom d'utilisateur
            password: Mot de passe en clair
            
        Returns:
            User: Utilisateur authentifié ou None en cas d'échec
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Récupérer l'utilisateur
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user_data = cursor.fetchone()
            
            if not user_data:
                logger.warning(f"Tentative d'authentification avec un utilisateur inexistant: {username}")
                return None
            
            # Convertir les données en objet User
            user = User(
                id=user_data[0],
                username=user_data[1],
                email=user_data[2],
                password_hash=user_data[3],
                role=user_data[4],
                created_at=user_data[5],
                last_login=user_data[6]
            )
            
            # Vérifier le mot de passe
            if bcrypt.checkpw(password.encode(), user.password_hash.encode()):
                # Mettre à jour la date de dernière connexion
                now = datetime.datetime.now().isoformat()
                cursor.execute("UPDATE users SET last_login = ? WHERE id = ?", (now, user.id))
                conn.commit()
                
                user.last_login = now
                logger.info(f"Utilisateur {username} authentifié avec succès")
                return user
            else:
                logger.warning(f"Échec d'authentification pour l'utilisateur {username}: mot de passe incorrect")
                return None
        
        except Exception as e:
            logger.error(f"Erreur lors de l'authentification: {e}")
            return None
        
        finally:
            conn.close()
    
    def get_user_by_id(self, user_id):
        """
        Récupère un utilisateur par son ID.
        
        Args:
            user_id: ID de l'utilisateur
            
        Returns:
            User: Utilisateur ou None s'il n'existe pas
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            user_data = cursor.fetchone()
            
            conn.close()
            
            if not user_data:
                return None
            
            return User(
                id=user_data[0],
                username=user_data[1],
                email=user_data[2],
                password_hash=user_data[3],
                role=user_data[4],
                created_at=user_data[5],
                last_login=user_data[6]
            )
        
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de l'utilisateur: {e}")
            return None
    
    def get_user_by_username(self, username):
        """
        Récupère un utilisateur par son nom d'utilisateur.
        
        Args:
            username: Nom d'utilisateur
            
        Returns:
            User: Utilisateur ou None s'il n'existe pas
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user_data = cursor.fetchone()
            
            conn.close()
            
            if not user_data:
                return None
            
            return User(
                id=user_data[0],
                username=user_data[1],
                email=user_data[2],
                password_hash=user_data[3],
                role=user_data[4],
                created_at=user_data[5],
                last_login=user_data[6]
            )
        
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de l'utilisateur: {e}")
            return None
    
    def update_user(self, user_id, **kwargs):
        """
        Met à jour un utilisateur.
        
        Args:
            user_id: ID de l'utilisateur
            **kwargs: Champs à mettre à jour
            
        Returns:
            bool: True si la mise à jour a réussi, False sinon
        """
        try:
            # Récupérer l'utilisateur
            user = self.get_user_by_id(user_id)
            if not user:
                logger.error(f"Utilisateur inexistant: {user_id}")
                return False
            
            # Préparer les champs à mettre à jour
            fields = []
            values = []
            
            if "username" in kwargs:
                fields.append("username = ?")
                values.append(kwargs["username"])
            
            if "email" in kwargs:
                fields.append("email = ?")
                values.append(kwargs["email"])
            
            if "password" in kwargs:
                password_hash = bcrypt.hashpw(kwargs["password"].encode(), bcrypt.gensalt()).decode()
                fields.append("password_hash = ?")
                values.append(password_hash)
            
            if "role" in kwargs and kwargs["role"] in ROLES:
                fields.append("role = ?")
                values.append(kwargs["role"])
            
            if not fields:
                logger.warning("Aucun champ à mettre à jour")
                return False
            
            # Mettre à jour l'utilisateur
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            query = f"UPDATE users SET {', '.join(fields)} WHERE id = ?"
            values.append(user_id)
            
            cursor.execute(query, values)
            conn.commit()
            conn.close()
            
            logger.info(f"Utilisateur {user_id} mis à jour avec succès")
            return True
        
        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour de l'utilisateur: {e}")
            return False
    
    def delete_user(self, user_id):
        """
        Supprime un utilisateur.
        
        Args:
            user_id: ID de l'utilisateur
            
        Returns:
            bool: True si la suppression a réussi, False sinon
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Supprimer les sessions de l'utilisateur
            cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            
            # Supprimer l'utilisateur
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            
            if cursor.rowcount == 0:
                logger.warning(f"Tentative de suppression d'un utilisateur inexistant: {user_id}")
                conn.close()
                return False
            
            conn.commit()
            conn.close()
            
            logger.info(f"Utilisateur {user_id} supprimé avec succès")
            return True
        
        except Exception as e:
            logger.error(f"Erreur lors de la suppression de l'utilisateur: {e}")
            return False
    
    def list_users(self):
        """
        Liste tous les utilisateurs.
        
        Returns:
            list: Liste des utilisateurs
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM users")
            users_data = cursor.fetchall()
            
            conn.close()
            
            users = []
            for user_data in users_data:
                users.append(User(
                    id=user_data[0],
                    username=user_data[1],
                    email=user_data[2],
                    password_hash=user_data[3],
                    role=user_data[4],
                    created_at=user_data[5],
                    last_login=user_data[6]
                ))
            
            return users
        
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des utilisateurs: {e}")
            return []
    
    def create_jwt_token(self, user):
        """
        Crée un token JWT pour un utilisateur.
        
        Args:
            user: Utilisateur
            
        Returns:
            str: Token JWT
        """
        now = datetime.datetime.utcnow()
        expiration = now + datetime.timedelta(seconds=JWT_EXPIRATION)
        
        payload = {
            "sub": user.id,
            "username": user.username,
            "role": user.role,
            "iat": now.timestamp(),
            "exp": expiration.timestamp()
        }
        
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
        
        # Enregistrer la session
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute(
                "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (
                    token,
                    user.id,
                    now.isoformat(),
                    expiration.isoformat()
                )
            )
            
            conn.commit()
            conn.close()
        
        except Exception as e:
            logger.error(f"Erreur lors de l'enregistrement de la session: {e}")
        
        return token
    
    def verify_jwt_token(self, token):
        """
        Vérifie un token JWT.
        
        Args:
            token: Token JWT
            
        Returns:
            User: Utilisateur associé au token ou None si le token est invalide
        """
        try:
            # Vérifier que le token existe dans la base de données
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM sessions WHERE token = ?", (token,))
            session_data = cursor.fetchone()
            
            if not session_data:
                logger.warning("Token JWT inexistant dans la base de données")
                conn.close()
                return None
            
            # Vérifier que le token n'est pas expiré
            expires_at = datetime.datetime.fromisoformat(session_data[3])
            if expires_at < datetime.datetime.utcnow():
                logger.warning("Token JWT expiré")
                
                # Supprimer la session
                cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
                conn.commit()
                conn.close()
                
                return None
            
            # Décoder le token
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            
            # Récupérer l'utilisateur
            user_id = payload["sub"]
            user = self.get_user_by_id(user_id)
            
            conn.close()
            
            return user
        
        except jwt.ExpiredSignatureError:
            logger.warning("Token JWT expiré")
            return None
        
        except jwt.InvalidTokenError:
            logger.warning("Token JWT invalide")
            return None
        
        except Exception as e:
            logger.error(f"Erreur lors de la vérification du token JWT: {e}")
            return None
    
    def revoke_jwt_token(self, token):
        """
        Révoque un token JWT.
        
        Args:
            token: Token JWT
            
        Returns:
            bool: True si la révocation a réussi, False sinon
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
            
            if cursor.rowcount == 0:
                logger.warning(f"Tentative de révocation d'un token inexistant")
                conn.close()
                return False
            
            conn.commit()
            conn.close()
            
            logger.info("Token JWT révoqué avec succès")
            return True
        
        except Exception as e:
            logger.error(f"Erreur lors de la révocation du token JWT: {e}")
            return False
    
    def revoke_all_user_tokens(self, user_id):
        """
        Révoque tous les tokens d'un utilisateur.
        
        Args:
            user_id: ID de l'utilisateur
            
        Returns:
            bool: True si la révocation a réussi, False sinon
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Tous les tokens de l'utilisateur {user_id} ont été révoqués")
            return True
        
        except Exception as e:
            logger.error(f"Erreur lors de la révocation des tokens: {e}")
            return False
    
    def cleanup_expired_sessions(self):
        """
        Nettoie les sessions expirées.
        
        Returns:
            int: Nombre de sessions supprimées
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            now = datetime.datetime.utcnow().isoformat()
            cursor.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            
            count = cursor.rowcount
            conn.commit()
            conn.close()
            
            if count > 0:
                logger.info(f"{count} sessions expirées ont été supprimées")
            
            return count
        
        except Exception as e:
            logger.error(f"Erreur lors du nettoyage des sessions: {e}")
            return 0

# Fonctions de décorateur pour la protection des routes
def login_required(f):
    """Décorateur pour vérifier qu'un utilisateur est connecté."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Cette fonction sera implémentée dans le module web
        # Elle vérifiera la présence d'un token JWT valide
        pass
    return decorated_function

def role_required(role):
    """Décorateur pour vérifier qu'un utilisateur a un rôle spécifique."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Cette fonction sera implémentée dans le module web
            # Elle vérifiera que l'utilisateur a le rôle requis
            pass
        return decorated_function
    return decorator

# Fonctions d'authentification HTTP Basic
def parse_basic_auth(auth_header):
    """
    Parse un en-tête d'authentification HTTP Basic.
    
    Args:
        auth_header: En-tête d'authentification
        
    Returns:
        tuple: (username, password) ou (None, None) si l'en-tête est invalide
    """
    import base64
    
    if not auth_header or not auth_header.startswith("Basic "):
        return None, None
    
    try:
        auth_decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
        username, password = auth_decoded.split(":", 1)
        return username, password
    except Exception as e:
        logger.error(f"Erreur lors du parsing de l'en-tête Basic Auth: {e}")
        return None, None

# Point d'entrée pour les tests
def run_auth_test():
    """Fonction de test pour le module d'authentification."""
    auth_manager = AuthManager()
    
    # Créer un utilisateur de test
    test_user = auth_manager.register_user(
        username="test_user",
        email="test@example.com",
        password="password123",
        role="pentester"
    )
    
    if test_user:
        print(f"Utilisateur créé: {test_user.username} (ID: {test_user.id})")
        
        # Authentifier l'utilisateur
        authenticated_user = auth_manager.authenticate("test_user", "password123")
        if authenticated_user:
            print(f"Authentification réussie pour {authenticated_user.username}")
            
            # Créer un token JWT
            token = auth_manager.create_jwt_token(authenticated_user)
            print(f"Token JWT: {token}")
            
            # Vérifier le token
            verified_user = auth_manager.verify_jwt_token(token)
            if verified_user:
                print(f"Token vérifié pour {verified_user.username}")
            else:
                print("Échec de la vérification du token")
            
            # Révoquer le token
            if auth_manager.revoke_jwt_token(token):
                print("Token révoqué avec succès")
            else:
                print("Échec de la révocation du token")
        else:
            print("Échec de l'authentification")
        
        # Supprimer l'utilisateur de test
        if auth_manager.delete_user(test_user.id):
            print(f"Utilisateur {test_user.username} supprimé avec succès")
        else:
            print(f"Échec de la suppression de l'utilisateur {test_user.username}")
    else:
        print("Échec de la création de l'utilisateur")

if __name__ == "__main__":
    run_auth_test()
