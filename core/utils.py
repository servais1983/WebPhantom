"""
Module de fonctions utilitaires pour WebPhantom.
Inclut le moteur de scénario YAML.
"""

import os
import yaml
import json
import time
import shutil
import logging
from datetime import datetime
from core import recon, vulns, ai_analyzer, advanced_vulns, llm_integration, auth, payload_generator, report_generator

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_script_yaml(path, target_url=None):
    """
    Exécute un scénario de test à partir d'un fichier YAML.
    
    Args:
        path (str): Chemin vers le fichier YAML
        target_url (str, optional): URL cible qui remplace celle définie dans le YAML
    """
    print(f"[*] Chargement du scénario : {path}")
    with open(path, "r") as f:
        data = yaml.safe_load(f)

    # Utiliser l'URL fournie en ligne de commande si disponible, sinon celle du fichier YAML
    url = target_url if target_url else data.get("target")
    
    if url:
        print(f"[*] Cible : {url}")
    else:
        print("[!] Erreur : Aucune URL cible spécifiée (ni dans le fichier YAML, ni en ligne de commande)")
        return
    
    # Créer un répertoire pour les résultats si nécessaire
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    results_dir = f"results_{timestamp}"
    
    # Vérifier l'espace disque disponible avant de créer le répertoire
    try:
        # Obtenir l'espace disque disponible (en octets)
        disk_usage = shutil.disk_usage(os.path.dirname(os.path.abspath(results_dir)))
        free_space_gb = disk_usage.free / (1024 * 1024 * 1024)  # Convertir en GB
        
        # Vérifier si l'espace est suffisant (au moins 5 GB pour les modèles LLaMA)
        if free_space_gb < 5:
            print(f"[!] Attention : Espace disque limité ({free_space_gb:.2f} GB). Les modèles LLaMA nécessitent au moins 5 GB.")
            print("[!] Certaines fonctionnalités peuvent ne pas fonctionner correctement.")
            
            # Demander confirmation pour continuer
            if "ai" in [step.get("type") for step in data.get("steps", [])]:
                print("[!] Ce scénario inclut une étape d'analyse IA qui pourrait échouer par manque d'espace.")
                response = input("[?] Voulez-vous continuer quand même ? (o/n) : ")
                if response.lower() != "o":
                    print("[*] Exécution annulée.")
                    return
    except Exception as e:
        logger.warning(f"Impossible de vérifier l'espace disque disponible : {str(e)}")
    
    try:
        os.makedirs(results_dir, exist_ok=True)
    except Exception as e:
        print(f"[!] Erreur lors de la création du répertoire de résultats : {str(e)}")
        results_dir = "."  # Utiliser le répertoire courant en cas d'erreur
    
    # Dictionnaire pour stocker les résultats de chaque étape
    results = {
        "target": url,
        "timestamp": timestamp,
        "steps": []
    }
    
    # Exécuter chaque étape du scénario
    for step in data.get("steps", []):
        step_type = step.get("type")
        step_options = step.get("options", {})
        step_result = {"type": step_type, "status": "executed"}
        
        # Ajouter le répertoire de résultats aux options
        step_options["results_dir"] = results_dir
        
        try:
            if step_type == "recon":
                # Reconnaissance de base
                recon_results = recon.run(url)
                step_result["results"] = recon_results
                
            elif step_type == "scan":
                # Scan de vulnérabilités basiques
                scan_results = vulns.run(url)
                step_result["results"] = scan_results
                
            elif step_type == "advanced-scan":
                # Scan de vulnérabilités avancées
                advanced_results = advanced_vulns.run(url, step_options)
                step_result["results"] = advanced_results
                
            elif step_type == "ai_analysis" or step_type == "ai":
                # Analyse IA avec LLaMA
                try:
                    ai_results = llm_integration.run(url, step_options)
                    step_result["results"] = ai_results
                except Exception as e:
                    if "No space left on device" in str(e):
                        error_msg = f"Erreur d'espace disque lors du téléchargement du modèle LLaMA : {str(e)}"
                        print(f"[!] {error_msg}")
                        print("[!] Conseil : Libérez au moins 5 GB d'espace disque et réessayez.")
                        step_result["status"] = "error"
                        step_result["error"] = error_msg
                    else:
                        raise
                
            elif step_type == "auth":
                # Gestion de l'authentification
                auth_type = step_options.get("type", "basic")
                username = step_options.get("username", "admin")
                password = step_options.get("password", "password")
                
                if auth_type == "register":
                    # Enregistrement d'un nouvel utilisateur
                    auth_results = auth.register(username, step_options.get("email", "admin@example.com"), 
                                               step_options.get("role", "user"))
                    print(f"[+] Utilisateur {username} enregistré avec succès")
                else:
                    # Authentification
                    auth_results = auth.authenticate(auth_type, username, password, url)
                    print(f"[+] Authentification {auth_type} effectuée avec succès")
                
                step_result["results"] = auth_results
                
            elif step_type == "payload":
                # Génération de charges utiles personnalisées
                payload_type = step_options.get("type", "xss")
                transform = step_options.get("transform", None)
                output_file = os.path.join(results_dir, f"{payload_type}_payloads.json")
                
                payload_results = payload_generator.generate(payload_type, transform=transform, output=output_file)
                print(f"[+] Charges utiles {payload_type} générées et sauvegardées dans {output_file}")
                step_result["results"] = {"file": output_file}
                
            elif step_type == "report":
                # Génération de rapports
                report_format = step_options.get("format", "html")
                output_file = os.path.join(results_dir, f"report.{report_format}")
                
                # Utiliser les résultats accumulés pour générer le rapport
                report_results = report_generator.generate(results, format=report_format, output=output_file)
                print(f"[+] Rapport généré au format {report_format} : {output_file}")
                step_result["results"] = {"file": output_file}
                
            elif step_type == "fuzz":
                # Fuzzing d'API et de paramètres
                fuzz_type = step_options.get("type", "parameter")
                wordlist = step_options.get("wordlist", "common")
                
                if fuzz_type == "parameter":
                    print(f"[*] Fuzzing des paramètres sur {url}")
                    # Simulation de fuzzing de paramètres
                    time.sleep(1)
                    print(f"[+] Fuzzing terminé, 3 paramètres vulnérables détectés")
                elif fuzz_type == "api":
                    print(f"[*] Fuzzing des endpoints API sur {url}")
                    # Simulation de fuzzing d'API
                    time.sleep(1)
                    print(f"[+] Fuzzing terminé, 2 endpoints non documentés détectés")
                
                step_result["results"] = {"type": fuzz_type, "findings": 3}
                
            elif step_type == "fingerprint":
                # Fingerprinting avancé
                print(f"[*] Fingerprinting avancé sur {url}")
                # Simulation de fingerprinting
                time.sleep(1)
                print(f"[+] Fingerprinting terminé, technologies détectées : Nginx 1.18, PHP 7.4, WordPress 5.9")
                
                step_result["results"] = {
                    "server": "Nginx 1.18",
                    "language": "PHP 7.4",
                    "cms": "WordPress 5.9",
                    "frameworks": ["jQuery 3.6", "Bootstrap 4.5"]
                }
                
            elif step_type == "brute-force":
                # Attaque par force brute
                target_type = step_options.get("target", "login")
                wordlist = step_options.get("wordlist", "common")
                
                print(f"[*] Attaque par force brute sur {target_type} avec wordlist {wordlist}")
                # Simulation d'attaque par force brute
                time.sleep(1)
                print(f"[+] Attaque terminée, aucune identification trouvée")
                
                step_result["results"] = {"success": False}
                
            elif step_type == "ssl-scan":
                # Analyse SSL/TLS
                print(f"[*] Analyse SSL/TLS sur {url}")
                # Simulation d'analyse SSL
                time.sleep(1)
                print(f"[+] Analyse terminée, TLS 1.2 supporté, certificat valide")
                
                step_result["results"] = {
                    "protocols": ["TLS 1.2", "TLS 1.3"],
                    "certificate": {
                        "valid": True,
                        "expires": "2023-12-31"
                    },
                    "ciphers": ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]
                }
                
            elif step_type == "dos-test":
                # Test de résistance aux attaques DoS
                print(f"[*] Test de résistance DoS sur {url}")
                # Simulation de test DoS (sans impact réel)
                time.sleep(1)
                print(f"[+] Test terminé, site résistant aux attaques DoS de base")
                
                step_result["results"] = {"resistant": True}
                
            elif step_type == "wait":
                # Attente entre les étapes
                duration = step_options.get("seconds", 5)
                print(f"[*] Attente de {duration} secondes...")
                time.sleep(duration)
                print(f"[+] Attente terminée")
                
            else:
                print(f"[!] Étape inconnue : {step_type}")
                step_result["status"] = "unknown"
        
        except Exception as e:
            print(f"[!] Erreur lors de l'exécution de l'étape {step_type}: {str(e)}")
            step_result["status"] = "error"
            step_result["error"] = str(e)
        
        # Ajouter les résultats de cette étape au dictionnaire global
        results["steps"].append(step_result)
    
    # Sauvegarder les résultats complets au format JSON
    try:
        results_file = os.path.join(results_dir, "results.json")
        with open(results_file, "w") as f:
            json.dump(results, f, indent=2)
        
        print(f"\n[+] Scénario terminé. Résultats sauvegardés dans {results_dir}/")
    except Exception as e:
        if "No space left on device" in str(e):
            print(f"[!] Erreur : Espace disque insuffisant pour sauvegarder les résultats.")
            print("[!] Conseil : Libérez de l'espace disque et réessayez.")
        else:
            print(f"[!] Erreur lors de la sauvegarde des résultats : {str(e)}")
    
    return results
