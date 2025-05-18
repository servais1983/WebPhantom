"""
Module de scan avancé de vulnérabilités pour WebPhantom.
Détecte CSRF, SSRF, XXE, IDOR et autres vulnérabilités avancées.
"""

import requests
import logging
import re
import json
import random
import time
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, urljoin

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run(url, options=None):
    """
    Fonction principale pour le scan avancé de vulnérabilités.
    
    Args:
        url (str): URL cible
        options (dict, optional): Options de scan
        
    Returns:
        dict: Résultats du scan
    """
    if not options:
        options = {}
    
    results = {
        "target": url,
        "vulnerabilities": [],
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    
    print(f"[*] Scan avancé de vulnérabilités sur {url}")
    
    # Déterminer quels scans effectuer
    scan_csrf = options.get("scan_csrf", True)
    scan_ssrf = options.get("scan_ssrf", True)
    scan_xxe = options.get("scan_xxe", True)
    scan_idor = options.get("scan_idor", True)
    scan_ssti = options.get("scan_ssti", True)
    
    # Effectuer les scans sélectionnés
    if scan_csrf:
        csrf_results = scan_csrf_vulnerability(url)
        if csrf_results:
            results["vulnerabilities"].append(csrf_results)
    
    if scan_ssrf:
        ssrf_results = scan_ssrf_vulnerability(url)
        if ssrf_results:
            results["vulnerabilities"].append(ssrf_results)
    
    if scan_xxe:
        xxe_results = scan_xxe_vulnerability(url)
        if xxe_results:
            results["vulnerabilities"].append(xxe_results)
    
    if scan_idor:
        idor_results = scan_idor_vulnerability(url)
        if idor_results:
            results["vulnerabilities"].append(idor_results)
    
    if scan_ssti:
        ssti_results = scan_ssti_vulnerability(url)
        if ssti_results:
            results["vulnerabilities"].append(ssti_results)
    
    # Afficher un résumé des résultats
    vuln_count = len(results["vulnerabilities"])
    if vuln_count > 0:
        print(f"[+] {vuln_count} vulnérabilité(s) avancée(s) détectée(s)")
        for vuln in results["vulnerabilities"]:
            print(f"  - {vuln['type']}: {vuln['description']}")
    else:
        print("[-] Aucune vulnérabilité avancée détectée")
    
    return results

def scan_csrf_vulnerability(url):
    """
    Scan de vulnérabilités CSRF.
    
    Args:
        url (str): URL cible
        
    Returns:
        dict: Résultat du scan CSRF
    """
    logger.info(f"Scan CSRF sur {url}")
    try:
        # Récupérer la page
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Rechercher des formulaires
        forms = soup.find_all('form')
        if not forms:
            return None
        
        # Vérifier la présence de tokens CSRF dans les formulaires
        for form in forms:
            csrf_token = form.find('input', attrs={'name': re.compile('csrf|token', re.I)})
            if not csrf_token:
                # Formulaire sans protection CSRF détecté
                action = form.get('action', '')
                method = form.get('method', 'get').upper()
                
                return {
                    "type": "CSRF",
                    "severity": "Medium",
                    "description": f"Formulaire sans protection CSRF détecté ({method} {action})",
                    "evidence": str(form)[:200] + "..." if len(str(form)) > 200 else str(form),
                    "location": urljoin(url, action) if action else url
                }
        
        return None
    except Exception as e:
        logger.error(f"Erreur lors du scan CSRF: {str(e)}")
        return None

def scan_ssrf_vulnerability(url):
    """
    Scan de vulnérabilités SSRF.
    
    Args:
        url (str): URL cible
        
    Returns:
        dict: Résultat du scan SSRF
    """
    logger.info(f"Scan SSRF sur {url}")
    try:
        # Analyser l'URL pour trouver des paramètres potentiellement vulnérables
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        ssrf_params = []
        for param, values in query_params.items():
            if any(keyword in param.lower() for keyword in ['url', 'link', 'path', 'src', 'dest', 'redirect', 'uri', 'source']):
                ssrf_params.append(param)
        
        if not ssrf_params:
            return None
        
        # Paramètre potentiellement vulnérable trouvé
        return {
            "type": "SSRF",
            "severity": "High",
            "description": f"Paramètre(s) potentiellement vulnérable(s) aux attaques SSRF: {', '.join(ssrf_params)}",
            "evidence": url,
            "location": url
        }
    except Exception as e:
        logger.error(f"Erreur lors du scan SSRF: {str(e)}")
        return None

def scan_xxe_vulnerability(url):
    """
    Scan de vulnérabilités XXE.
    
    Args:
        url (str): URL cible
        
    Returns:
        dict: Résultat du scan XXE
    """
    logger.info(f"Scan XXE sur {url}")
    try:
        # Récupérer la page
        response = requests.get(url)
        
        # Vérifier si la page accepte du XML
        content_type = response.headers.get('Content-Type', '')
        if 'xml' in content_type.lower():
            return {
                "type": "XXE",
                "severity": "High",
                "description": "Endpoint acceptant du XML détecté, potentiellement vulnérable aux attaques XXE",
                "evidence": f"Content-Type: {content_type}",
                "location": url
            }
        
        # Rechercher des formulaires qui pourraient accepter du XML
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form', attrs={'enctype': re.compile('xml', re.I)})
        if forms:
            return {
                "type": "XXE",
                "severity": "High",
                "description": "Formulaire acceptant du XML détecté, potentiellement vulnérable aux attaques XXE",
                "evidence": str(forms[0])[:200] + "..." if len(str(forms[0])) > 200 else str(forms[0]),
                "location": url
            }
        
        return None
    except Exception as e:
        logger.error(f"Erreur lors du scan XXE: {str(e)}")
        return None

def scan_idor_vulnerability(url):
    """
    Scan de vulnérabilités IDOR.
    
    Args:
        url (str): URL cible
        
    Returns:
        dict: Résultat du scan IDOR
    """
    logger.info(f"Scan IDOR sur {url}")
    try:
        # Analyser l'URL pour trouver des identifiants numériques
        parsed_url = urlparse(url)
        path_segments = parsed_url.path.split('/')
        query_params = parse_qs(parsed_url.query)
        
        # Rechercher des identifiants numériques dans le chemin
        for segment in path_segments:
            if segment.isdigit():
                return {
                    "type": "IDOR",
                    "severity": "High",
                    "description": f"Identifiant numérique {segment} détecté dans l'URL, potentiellement vulnérable aux attaques IDOR",
                    "evidence": url,
                    "location": url
                }
        
        # Rechercher des identifiants numériques dans les paramètres
        for param, values in query_params.items():
            if any(value.isdigit() for value in values) and any(keyword in param.lower() for keyword in ['id', 'user', 'account', 'num', 'doc', 'key']):
                return {
                    "type": "IDOR",
                    "severity": "High",
                    "description": f"Paramètre {param} avec valeur numérique détecté, potentiellement vulnérable aux attaques IDOR",
                    "evidence": url,
                    "location": url
                }
        
        return None
    except Exception as e:
        logger.error(f"Erreur lors du scan IDOR: {str(e)}")
        return None

def scan_ssti_vulnerability(url):
    """
    Scan de vulnérabilités SSTI (Server-Side Template Injection).
    
    Args:
        url (str): URL cible
        
    Returns:
        dict: Résultat du scan SSTI
    """
    logger.info(f"Scan SSTI sur {url}")
    try:
        # Générer un payload de test pour SSTI
        test_value = f"${{7*7}}"
        
        # Analyser l'URL pour trouver des paramètres à tester
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        if not query_params:
            return None
        
        # Tester le premier paramètre trouvé
        param = list(query_params.keys())[0]
        test_url = url.replace(f"{param}={query_params[param][0]}", f"{param}={test_value}")
        
        # Envoyer la requête avec le payload
        response = requests.get(test_url)
        
        # Vérifier si le résultat de l'évaluation (49) est présent dans la réponse
        if "49" in response.text:
            return {
                "type": "SSTI",
                "severity": "Critical",
                "description": f"Potentielle vulnérabilité d'injection de template (SSTI) détectée dans le paramètre {param}",
                "evidence": test_url,
                "location": url
            }
        
        return None
    except Exception as e:
        logger.error(f"Erreur lors du scan SSTI: {str(e)}")
        return None
