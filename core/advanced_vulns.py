"""
Module de scan avancé de vulnérabilités web.
Ce module étend les capacités de détection de vulnérabilités avec des tests
plus sophistiqués pour CSRF, SSRF, XXE, IDOR et autres vulnérabilités avancées.
"""

import re
import json
import logging
import requests
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("advanced_vulns")

# Dictionnaire des vulnérabilités et leurs descriptions
VULN_DESCRIPTIONS = {
    "CSRF": "Cross-Site Request Forgery - Permet à un attaquant de forcer un utilisateur à exécuter des actions non désirées sur une application web où il est authentifié.",
    "SSRF": "Server-Side Request Forgery - Permet à un attaquant de forcer le serveur à effectuer des requêtes HTTP vers des ressources internes ou externes.",
    "XXE": "XML External Entity - Permet à un attaquant d'accéder à des fichiers locaux ou des services internes via des entités XML externes.",
    "IDOR": "Insecure Direct Object References - Permet à un attaquant d'accéder directement à des objets internes de l'application en manipulant les références.",
    "CORS": "Cross-Origin Resource Sharing mal configuré - Peut permettre à des sites malveillants d'accéder à des données sensibles.",
    "JWT": "JSON Web Token vulnérable - Tokens mal sécurisés pouvant être manipulés ou décodés.",
    "SSTI": "Server-Side Template Injection - Permet l'injection de code dans les templates côté serveur.",
    "CRLF": "Carriage Return Line Feed Injection - Permet la manipulation des en-têtes HTTP et potentiellement des attaques de type HTTP Response Splitting.",
    "OpenRedirect": "Open Redirect - Permet à un attaquant de rediriger les utilisateurs vers des sites malveillants.",
    "RCE": "Remote Code Execution - Permet l'exécution de code arbitraire sur le serveur distant."
}

class VulnerabilityResult:
    """Classe pour stocker les résultats des tests de vulnérabilité."""
    
    def __init__(self, vuln_type, url, details, severity="Medium", evidence=None, remediation=None):
        self.vuln_type = vuln_type
        self.url = url
        self.details = details
        self.severity = severity  # Critical, High, Medium, Low, Info
        self.evidence = evidence or {}
        self.remediation = remediation or []
        self.timestamp = None  # Sera défini lors de la génération du rapport
    
    def to_dict(self):
        """Convertit le résultat en dictionnaire."""
        return {
            "type": self.vuln_type,
            "url": self.url,
            "details": self.details,
            "severity": self.severity,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "timestamp": self.timestamp
        }
    
    def __str__(self):
        return f"[{self.severity}] {self.vuln_type}: {self.details} ({self.url})"

def test_csrf(url, session=None):
    """
    Teste la vulnérabilité CSRF en vérifiant l'absence de tokens anti-CSRF dans les formulaires.
    
    Args:
        url: URL à tester
        session: Session requests (optionnel)
        
    Returns:
        list: Liste des résultats de vulnérabilité
    """
    results = []
    session = session or requests.Session()
    
    try:
        response = session.get(url, timeout=10)
        if response.status_code != 200:
            return results
        
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for i, form in enumerate(forms):
            # Vérifier la présence de tokens anti-CSRF
            has_csrf_token = False
            
            # Recherche de champs cachés qui pourraient être des tokens CSRF
            hidden_inputs = form.find_all('input', type='hidden')
            for hidden in hidden_inputs:
                name = hidden.get('name', '').lower()
                if any(token_name in name for token_name in ['csrf', 'token', 'nonce', 'xsrf']):
                    has_csrf_token = True
                    break
            
            # Si aucun token CSRF n'est trouvé, signaler une vulnérabilité potentielle
            if not has_csrf_token and form.get('method', '').lower() != 'get':
                form_action = form.get('action', '')
                form_url = urljoin(url, form_action) if form_action else url
                
                results.append(VulnerabilityResult(
                    vuln_type="CSRF",
                    url=form_url,
                    details=f"Formulaire sans protection CSRF détecté (form #{i+1})",
                    severity="High",
                    evidence={
                        "form_id": form.get('id', f'form-{i+1}'),
                        "form_action": form_action,
                        "form_method": form.get('method', 'post')
                    },
                    remediation=[
                        "Implémenter des tokens anti-CSRF pour tous les formulaires non-GET",
                        "Utiliser des en-têtes SameSite=Strict pour les cookies",
                        "Vérifier l'en-tête Referer ou Origin pour les requêtes sensibles"
                    ]
                ))
    
    except Exception as e:
        logger.error(f"Erreur lors du test CSRF sur {url}: {e}")
    
    return results

def test_ssrf(url, session=None):
    """
    Teste la vulnérabilité SSRF en vérifiant les paramètres susceptibles d'être exploités.
    
    Args:
        url: URL à tester
        session: Session requests (optionnel)
        
    Returns:
        list: Liste des résultats de vulnérabilité
    """
    results = []
    session = session or requests.Session()
    
    # Liste des paramètres susceptibles d'être exploités pour SSRF
    ssrf_params = ['url', 'uri', 'link', 'src', 'href', 'path', 'dest', 'redirect', 'redirect_uri', 'callback', 'return_url', 'next', 'site', 'html', 'file', 'reference', 'ref']
    
    try:
        # Analyser l'URL pour extraire les paramètres
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Vérifier chaque paramètre
        for param_name, param_values in query_params.items():
            if any(ssrf_param in param_name.lower() for ssrf_param in ssrf_params):
                # Paramètre potentiellement vulnérable au SSRF
                results.append(VulnerabilityResult(
                    vuln_type="SSRF",
                    url=url,
                    details=f"Paramètre potentiellement vulnérable au SSRF: {param_name}",
                    severity="High",
                    evidence={
                        "parameter": param_name,
                        "value": param_values[0] if param_values else ""
                    },
                    remediation=[
                        "Valider et filtrer strictement les entrées utilisateur",
                        "Utiliser une liste blanche de domaines ou d'URLs autorisés",
                        "Implémenter des restrictions réseau au niveau du serveur",
                        "Éviter d'utiliser des fonctions qui font des requêtes HTTP basées sur des entrées utilisateur"
                    ]
                ))
        
        # Tester également les formulaires
        response = session.get(url, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for i, form in enumerate(forms):
                inputs = form.find_all('input')
                for input_field in inputs:
                    input_name = input_field.get('name', '').lower()
                    if any(ssrf_param in input_name for ssrf_param in ssrf_params):
                        form_action = form.get('action', '')
                        form_url = urljoin(url, form_action) if form_action else url
                        
                        results.append(VulnerabilityResult(
                            vuln_type="SSRF",
                            url=form_url,
                            details=f"Champ de formulaire potentiellement vulnérable au SSRF: {input_name}",
                            severity="High",
                            evidence={
                                "form_id": form.get('id', f'form-{i+1}'),
                                "input_name": input_name,
                                "input_type": input_field.get('type', 'text')
                            },
                            remediation=[
                                "Valider et filtrer strictement les entrées utilisateur",
                                "Utiliser une liste blanche de domaines ou d'URLs autorisés",
                                "Implémenter des restrictions réseau au niveau du serveur"
                            ]
                        ))
    
    except Exception as e:
        logger.error(f"Erreur lors du test SSRF sur {url}: {e}")
    
    return results

def test_xxe(url, session=None):
    """
    Teste la vulnérabilité XXE en vérifiant les points d'entrée XML.
    
    Args:
        url: URL à tester
        session: Session requests (optionnel)
        
    Returns:
        list: Liste des résultats de vulnérabilité
    """
    results = []
    session = session or requests.Session()
    
    try:
        # Vérifier les en-têtes de la réponse pour détecter les API XML
        response = session.head(url, timeout=5)
        content_type = response.headers.get('Content-Type', '').lower()
        
        if 'xml' in content_type:
            results.append(VulnerabilityResult(
                vuln_type="XXE",
                url=url,
                details="Point d'entrée XML détecté via Content-Type",
                severity="High",
                evidence={
                    "content_type": content_type
                },
                remediation=[
                    "Désactiver les entités externes XML dans le parser",
                    "Utiliser des parsers XML sécurisés qui désactivent DTD par défaut",
                    "Préférer JSON à XML quand c'est possible"
                ]
            ))
            return results
        
        # Vérifier si l'application accepte des requêtes XML
        xml_payload = """<?xml version="1.0" encoding="UTF-8"?>
        <test>test</test>"""
        
        headers = {'Content-Type': 'application/xml'}
        response = session.post(url, data=xml_payload, headers=headers, timeout=10)
        
        # Si la réponse est 200 OK, l'application pourrait accepter des entrées XML
        if response.status_code == 200:
            results.append(VulnerabilityResult(
                vuln_type="XXE",
                url=url,
                details="L'application accepte potentiellement des entrées XML",
                severity="Medium",
                evidence={
                    "response_code": response.status_code,
                    "response_length": len(response.text)
                },
                remediation=[
                    "Désactiver les entités externes XML dans le parser",
                    "Utiliser des parsers XML sécurisés qui désactivent DTD par défaut",
                    "Préférer JSON à XML quand c'est possible"
                ]
            ))
    
    except Exception as e:
        logger.error(f"Erreur lors du test XXE sur {url}: {e}")
    
    return results

def test_idor(url, session=None):
    """
    Teste la vulnérabilité IDOR en vérifiant les paramètres d'ID dans l'URL.
    
    Args:
        url: URL à tester
        session: Session requests (optionnel)
        
    Returns:
        list: Liste des résultats de vulnérabilité
    """
    results = []
    session = session or requests.Session()
    
    # Patterns d'ID courants dans les URLs
    id_patterns = [
        r'id=(\d+)',
        r'user_?id=(\d+)',
        r'item_?id=(\d+)',
        r'profile_?id=(\d+)',
        r'order_?id=(\d+)',
        r'account_?id=(\d+)',
        r'record_?id=(\d+)',
        r'/(\d+)$',
        r'/user/(\d+)',
        r'/profile/(\d+)',
        r'/item/(\d+)',
        r'/order/(\d+)'
    ]
    
    try:
        # Vérifier si l'URL contient des patterns d'ID
        for pattern in id_patterns:
            matches = re.search(pattern, url)
            if matches:
                id_value = matches.group(1)
                
                results.append(VulnerabilityResult(
                    vuln_type="IDOR",
                    url=url,
                    details=f"Référence directe à un objet détectée: {matches.group(0)}",
                    severity="High",
                    evidence={
                        "pattern": pattern,
                        "id_value": id_value
                    },
                    remediation=[
                        "Utiliser des références indirectes aux objets (ex: GUID aléatoires)",
                        "Implémenter un contrôle d'accès strict pour chaque objet",
                        "Vérifier que l'utilisateur a le droit d'accéder à l'objet demandé"
                    ]
                ))
    
    except Exception as e:
        logger.error(f"Erreur lors du test IDOR sur {url}: {e}")
    
    return results

def test_cors(url, session=None):
    """
    Teste les mauvaises configurations CORS.
    
    Args:
        url: URL à tester
        session: Session requests (optionnel)
        
    Returns:
        list: Liste des résultats de vulnérabilité
    """
    results = []
    session = session or requests.Session()
    
    try:
        # Tester avec un Origin malveillant
        headers = {'Origin': 'https://malicious-site.com'}
        response = session.get(url, headers=headers, timeout=10)
        
        # Vérifier l'en-tête Access-Control-Allow-Origin
        acao = response.headers.get('Access-Control-Allow-Origin', '')
        acac = response.headers.get('Access-Control-Allow-Credentials', '')
        
        if acao == '*':
            results.append(VulnerabilityResult(
                vuln_type="CORS",
                url=url,
                details="Configuration CORS permissive (Access-Control-Allow-Origin: *)",
                severity="Medium",
                evidence={
                    "acao": acao
                },
                remediation=[
                    "Limiter Access-Control-Allow-Origin à des domaines spécifiques",
                    "Ne pas utiliser l'origine générique '*' pour les API sensibles",
                    "Éviter d'utiliser Access-Control-Allow-Credentials avec des origines permissives"
                ]
            ))
        
        elif acao == 'https://malicious-site.com':
            severity = "High" if acac.lower() == 'true' else "Medium"
            
            results.append(VulnerabilityResult(
                vuln_type="CORS",
                url=url,
                details="Configuration CORS vulnérable (reflète l'origine sans validation)",
                severity=severity,
                evidence={
                    "acao": acao,
                    "acac": acac
                },
                remediation=[
                    "Valider strictement les origines autorisées",
                    "Ne pas refléter l'en-tête Origin sans validation",
                    "Utiliser une liste blanche d'origines autorisées"
                ]
            ))
    
    except Exception as e:
        logger.error(f"Erreur lors du test CORS sur {url}: {e}")
    
    return results

def test_jwt(url, session=None):
    """
    Teste les vulnérabilités liées aux JWT.
    
    Args:
        url: URL à tester
        session: Session requests (optionnel)
        
    Returns:
        list: Liste des résultats de vulnérabilité
    """
    results = []
    session = session or requests.Session()
    
    try:
        # Récupérer les cookies et les en-têtes Authorization
        response = session.get(url, timeout=10)
        
        # Vérifier les cookies pour les JWT
        cookies = response.cookies
        for cookie_name, cookie_value in cookies.items():
            if is_jwt(cookie_value):
                jwt_parts = cookie_value.split('.')
                
                if len(jwt_parts) == 3:
                    header = decode_jwt_part(jwt_parts[0])
                    
                    # Vérifier l'algorithme utilisé
                    if header and 'alg' in header:
                        alg = header['alg']
                        
                        if alg == 'none':
                            results.append(VulnerabilityResult(
                                vuln_type="JWT",
                                url=url,
                                details="JWT utilisant l'algorithme 'none'",
                                severity="Critical",
                                evidence={
                                    "cookie_name": cookie_name,
                                    "jwt_header": header
                                },
                                remediation=[
                                    "Ne jamais accepter l'algorithme 'none'",
                                    "Utiliser un algorithme sécurisé comme RS256"
                                ]
                            ))
                        
                        elif alg == 'HS256':
                            results.append(VulnerabilityResult(
                                vuln_type="JWT",
                                url=url,
                                details="JWT utilisant l'algorithme HS256 (potentiellement vulnérable si clé faible)",
                                severity="Medium",
                                evidence={
                                    "cookie_name": cookie_name,
                                    "jwt_header": header
                                },
                                remediation=[
                                    "Utiliser des clés secrètes fortes (au moins 256 bits)",
                                    "Considérer l'utilisation de RS256 avec des clés publiques/privées"
                                ]
                            ))
        
        # Vérifier l'en-tête Authorization
        auth_header = response.request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            jwt_token = auth_header[7:]  # Supprimer 'Bearer '
            
            if is_jwt(jwt_token):
                jwt_parts = jwt_token.split('.')
                
                if len(jwt_parts) == 3:
                    header = decode_jwt_part(jwt_parts[0])
                    
                    # Vérifier l'algorithme utilisé
                    if header and 'alg' in header:
                        alg = header['alg']
                        
                        if alg == 'none':
                            results.append(VulnerabilityResult(
                                vuln_type="JWT",
                                url=url,
                                details="JWT dans l'en-tête Authorization utilisant l'algorithme 'none'",
                                severity="Critical",
                                evidence={
                                    "header": "Authorization",
                                    "jwt_header": header
                                },
                                remediation=[
                                    "Ne jamais accepter l'algorithme 'none'",
                                    "Utiliser un algorithme sécurisé comme RS256"
                                ]
                            ))
                        
                        elif alg == 'HS256':
                            results.append(VulnerabilityResult(
                                vuln_type="JWT",
                                url=url,
                                details="JWT dans l'en-tête Authorization utilisant l'algorithme HS256 (potentiellement vulnérable si clé faible)",
                                severity="Medium",
                                evidence={
                                    "header": "Authorization",
                                    "jwt_header": header
                                },
                                remediation=[
                                    "Utiliser des clés secrètes fortes (au moins 256 bits)",
                                    "Considérer l'utilisation de RS256 avec des clés publiques/privées"
                                ]
                            ))
    
    except Exception as e:
        logger.error(f"Erreur lors du test JWT sur {url}: {e}")
    
    return results

def is_jwt(token):
    """
    Vérifie si une chaîne est un JWT valide.
    
    Args:
        token: Chaîne à vérifier
        
    Returns:
        bool: True si la chaîne est un JWT, False sinon
    """
    jwt_pattern = r'^[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*$'
    return bool(re.match(jwt_pattern, token))

def decode_jwt_part(encoded_part):
    """
    Décode une partie d'un JWT (header ou payload).
    
    Args:
        encoded_part: Partie encodée du JWT
        
    Returns:
        dict: Partie décodée ou None en cas d'erreur
    """
    import base64
    
    try:
        # Ajouter le padding si nécessaire
        padding = '=' * (4 - len(encoded_part) % 4)
        encoded_part = encoded_part + padding
        
        # Remplacer les caractères spéciaux de base64url par ceux de base64
        encoded_part = encoded_part.replace('-', '+').replace('_', '/')
        
        # Décoder
        decoded = base64.b64decode(encoded_part)
        return json.loads(decoded)
    except Exception as e:
        logger.error(f"Erreur lors du décodage du JWT: {e}")
        return None

def test_open_redirect(url, session=None):
    """
    Teste les vulnérabilités de redirection ouverte.
    
    Args:
        url: URL à tester
        session: Session requests (optionnel)
        
    Returns:
        list: Liste des résultats de vulnérabilité
    """
    results = []
    session = session or requests.Session()
    
    # Liste des paramètres susceptibles d'être exploités pour les redirections
    redirect_params = ['redirect', 'redirect_to', 'url', 'link', 'goto', 'return', 'return_url', 'return_to', 'next', 'redir', 'destination', 'dest', 'continue']
    
    try:
        # Analyser l'URL pour extraire les paramètres
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Vérifier chaque paramètre
        for param_name, param_values in query_params.items():
            if any(redirect_param in param_name.lower() for redirect_param in redirect_params):
                # Paramètre potentiellement vulnérable à la redirection ouverte
                results.append(VulnerabilityResult(
                    vuln_type="OpenRedirect",
                    url=url,
                    details=f"Paramètre potentiellement vulnérable à la redirection ouverte: {param_name}",
                    severity="Medium",
                    evidence={
                        "parameter": param_name,
                        "value": param_values[0] if param_values else ""
                    },
                    remediation=[
                        "Utiliser une liste blanche de domaines autorisés pour les redirections",
                        "Utiliser des redirections relatives plutôt qu'absolues",
                        "Implémenter une page intermédiaire de confirmation pour les redirections externes"
                    ]
                ))
    
    except Exception as e:
        logger.error(f"Erreur lors du test de redirection ouverte sur {url}: {e}")
    
    return results

def run_advanced_scan(url, session=None):
    """
    Exécute un scan avancé de vulnérabilités sur l'URL spécifiée.
    
    Args:
        url: URL à scanner
        session: Session requests (optionnel)
        
    Returns:
        list: Liste des résultats de vulnérabilité
    """
    results = []
    session = session or requests.Session()
    
    logger.info(f"Démarrage du scan avancé de vulnérabilités sur {url}")
    
    # Exécuter tous les tests de vulnérabilité
    results.extend(test_csrf(url, session))
    results.extend(test_ssrf(url, session))
    results.extend(test_xxe(url, session))
    results.extend(test_idor(url, session))
    results.extend(test_cors(url, session))
    results.extend(test_jwt(url, session))
    results.extend(test_open_redirect(url, session))
    
    # Afficher les résultats
    if results:
        logger.info(f"Scan terminé. {len(results)} vulnérabilités potentielles détectées.")
        for result in results:
            logger.info(str(result))
    else:
        logger.info("Scan terminé. Aucune vulnérabilité avancée détectée.")
    
    return results

def run(url):
    """
    Point d'entrée principal pour le scan avancé de vulnérabilités.
    
    Args:
        url: URL à scanner
    """
    print(f"[*] Scan avancé de vulnérabilités sur : {url}")
    
    try:
        session = requests.Session()
        results = run_advanced_scan(url, session)
        
        if results:
            print(f"[+] {len(results)} vulnérabilités potentielles détectées :")
            for result in results:
                severity_color = {
                    "Critical": "\033[91m",  # Rouge
                    "High": "\033[91m",      # Rouge
                    "Medium": "\033[93m",    # Jaune
                    "Low": "\033[94m",       # Bleu
                    "Info": "\033[92m"       # Vert
                }
                color = severity_color.get(result.severity, "\033[0m")
                reset = "\033[0m"
                print(f"  {color}[{result.severity}]{reset} {result.vuln_type}: {result.details}")
        else:
            print("[-] Aucune vulnérabilité avancée détectée.")
    
    except Exception as e:
        print(f"[!] Erreur lors du scan avancé : {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        run(sys.argv[1])
    else:
        print("Usage: python advanced_vulns.py <url>")
